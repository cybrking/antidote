"""Generates a standalone interactive HTML security report."""
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import ToolFinding, PropagationPath, ToolManifest

_SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}
_BLAST_FALLBACK = {"CRITICAL": 9, "HIGH": 6, "MED": 3, "LOW": 1}


def _build_report_data(
    findings: list[ToolFinding],
    paths: list[PropagationPath],
    tools: list[ToolManifest],
) -> dict:
    path_map = {p.entry_point: p for p in paths}
    tool_map = {t.tool_id: t for t in tools}

    counts = {"critical": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    for f in findings:
        key = _SEV_MAP.get(f.severity, "LOW").lower()
        if key in counts:
            counts[key] += 1

    all_perms: set[str] = set()
    for t in tools:
        all_perms.update(t.inferred_permissions)

    report_findings = []
    for f in findings:
        sev_html = _SEV_MAP.get(f.severity, "LOW")
        path = path_map.get(f.tool_id)
        tool = tool_map.get(f.tool_id)
        perms = list(tool.inferred_permissions) if tool else []
        title = f.description[:80] + ("..." if len(f.description) > 80 else "")
        narrative = path.control_summary if path else f.description
        kill_chain = path.kill_chain if path else []
        blast = path.blast_radius_score if path else _BLAST_FALLBACK.get(f.severity, 3)
        report_findings.append({
            "id": f.tool_id,
            "severity": sev_html,
            "type": f.vuln_type,
            "title": title,
            "description": f.description,
            "evidence": f.evidence,
            "blast_radius": blast,
            "permissions": perms,
            "kill_chain": kill_chain,
            "narrative": narrative,
            "remediation": [],
        })

    report_findings.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 99))

    total = len(findings)
    crits = counts["critical"]
    highs = counts["high"]
    parts = []
    if crits:
        parts.append(f"{crits} critical-severity")
    if highs:
        parts.append(f"{highs} high-severity")
    summary = f"Antidote scanned {len(tools)} tool(s) and identified {total} finding(s)"
    if parts:
        summary += f", including {' and '.join(parts)} issues requiring immediate attention"
    summary += ". Review each finding below and apply the recommended remediations before exposing these tools to untrusted clients."

    return {
        "scanner": "Antidote",
        "version": "v0.1.0",
        "target": f"{len(tools)} MCP tool(s)",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": 0,
        "tools_audited": len(tools),
        "permissions": sorted(all_perms),
        "summary": summary,
        "counts": counts,
        "findings": report_findings,
    }


def _build_graph_data(
    findings: list[ToolFinding],
    paths: list[PropagationPath],
    tools: list[ToolManifest],
) -> tuple[list, list]:
    finding_map = {f.tool_id: f for f in findings}
    W, H_MIN = 780, 400
    n = len(tools)
    H = max(H_MIN, n * 90 + 80)

    nodes: list[dict] = []
    edges: list[dict] = []

    nodes.append({"id": "user", "label": "User / Agent", "kind": "actor",
                  "x": 110, "y": H // 2})

    spacing = max(70, (H - 80) // max(n, 1))
    start_y = (H - (n - 1) * spacing) // 2

    right_ids: list[tuple[str, str, str]] = []

    for i, tool in enumerate(tools):
        f = finding_map.get(tool.tool_id)
        sev = f.severity if f else None
        label = tool.tool_name[:14]
        y = start_y + i * spacing
        nodes.append({"id": tool.tool_id, "label": label, "kind": "tool",
                      "x": 380, "y": y, "severity": sev})
        edges.append({"from": "user", "to": tool.tool_id, "kind": "call"})
        if "network.outbound" in tool.inferred_permissions:
            right_ids.append(("external", "External API", "external"))
        if "secrets.read" in tool.inferred_permissions:
            right_ids.append(("secrets", "secrets.read", "perm"))
        if "network.outbound" in tool.inferred_permissions:
            right_ids.append(("network", "network.outbound", "perm"))
        if "filesystem.read" in tool.inferred_permissions or "filesystem.write" in tool.inferred_permissions:
            right_ids.append(("filesystem", "filesystem", "perm"))

    seen: set[str] = set()
    right_unique = []
    for item in right_ids:
        if item[0] not in seen:
            seen.add(item[0])
            right_unique.append(item)

    r_spacing = H // max(len(right_unique), 1)
    for i, (nid, label, kind) in enumerate(right_unique):
        y = r_spacing // 2 + i * r_spacing
        nodes.append({"id": nid, "label": label, "kind": kind, "x": 660, "y": y})

    for path in paths:
        for reachable in path.reachable_tools:
            if reachable != path.entry_point:
                edges.append({"from": path.entry_point, "to": reachable,
                               "kind": "feeds", "risky": True})

    for tool in tools:
        if "external" in seen and "network.outbound" in tool.inferred_permissions:
            edges.append({"from": tool.tool_id, "to": "external",
                           "kind": "egress", "risky": True})
        if "secrets" in seen and "secrets.read" in tool.inferred_permissions:
            edges.append({"from": tool.tool_id, "to": "secrets",
                           "kind": "perm", "risky": True})
        if "network" in seen and "network.outbound" in tool.inferred_permissions:
            edges.append({"from": tool.tool_id, "to": "network", "kind": "perm"})
        if "filesystem" in seen and (
            "filesystem.read" in tool.inferred_permissions
            or "filesystem.write" in tool.inferred_permissions
        ):
            edges.append({"from": tool.tool_id, "to": "filesystem", "kind": "perm"})

    return nodes, edges, H


def write_html(
    findings: list[ToolFinding],
    paths: list[PropagationPath],
    tools: list[ToolManifest],
    output: Path,
) -> None:
    report_data = _build_report_data(findings, paths, tools)
    graph_nodes, graph_edges, graph_h = _build_graph_data(findings, paths, tools)
    html = _render(report_data, graph_nodes, graph_edges, graph_h)
    output.write_text(html, encoding="utf-8")


def _render(report_data: dict, graph_nodes: list, graph_edges: list, graph_h: int) -> str:
    report_json = json.dumps(report_data, indent=2)
    nodes_json = json.dumps(graph_nodes, indent=2)
    edges_json = json.dumps(graph_edges, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Antidote — MCP Security Scan Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,500;0,8..60,600;1,8..60,400&display=swap" rel="stylesheet" />
<style>
{_CSS}
</style>
</head>
<body>
<div id="root"></div>
<script src="https://unpkg.com/react@18.3.1/umd/react.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" crossorigin="anonymous"></script>

<script type="text/babel">
{_TWEAKS_PANEL_JSX}
</script>

<script type="text/babel">
const REPORT = {report_json};
window.REPORT = REPORT;
</script>

<script type="text/babel">
const GRAPH_NODES = {nodes_json};
const GRAPH_EDGES = {edges_json};
const GRAPH_H = {graph_h};
{_GRAPH_JSX}
</script>

<script type="text/babel">
{_FINDINGS_JSX}
</script>

<script type="text/babel">
{_APP_JSX}
</script>
</body>
</html>"""


_CSS = """
:root {
  --ink: #0f1014;
  --ink-2: #1f2128;
  --ink-3: #3a3d47;
  --paper: #fafaf7;
  --paper-2: #f3f2ec;
  --paper-3: #e8e6dd;
  --rule: #1f1f24;
  --rule-soft: #d9d6cc;
  --accent: #c81e3b;
  --accent-2: #a8182f;
  --warn: #c47900;
  --info: #2d5fb8;
  --ok: #2f7a4d;
  --sev-critical-bg: #1a0008;
  --sev-critical-fg: #ff8095;
  --sev-critical-bar: #e0103a;
  --sev-high-bg: #fde9ec;
  --sev-high-fg: #8a0d23;
  --sev-high-bar: #c81e3b;
  --sev-med-bg: #fdf2dc;
  --sev-med-fg: #6a4500;
  --sev-med-bar: #c47900;
  --sev-low-bg: #e7eef5;
  --sev-low-fg: #1d3f72;
  --sev-low-bar: #2d5fb8;
  --serif: "Source Serif 4","Source Serif Pro",Georgia,serif;
  --sans: "IBM Plex Sans",-apple-system,"Helvetica Neue",Arial,sans-serif;
  --mono: "IBM Plex Mono","JetBrains Mono",ui-monospace,Menlo,monospace;
  --radius: 4px;
  --shadow-card: 0 1px 0 rgba(15,16,20,.04),0 0 0 1px var(--rule-soft);
  --shadow-pop: 0 12px 32px rgba(15,16,20,.12),0 0 0 1px var(--rule-soft);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--ink);text-decoration:none}
mark{background:#fff3a8;color:inherit;padding:0 2px;border-radius:2px}
.app{max-width:1280px;margin:0 auto;padding:0 32px 80px}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:18px 0 16px;border-bottom:1px solid var(--rule);margin-bottom:28px;position:sticky;top:0;background:var(--paper);z-index:20}
.brand{display:flex;align-items:center;gap:12px;font-family:var(--mono);font-size:13px;letter-spacing:.02em}
.brand-mark{width:28px;height:28px;background:var(--ink);display:grid;place-items:center;position:relative}
.brand-mark::before{content:"";width:12px;height:12px;background:var(--accent);transform:rotate(45deg)}
.brand-name{font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.brand-sep,.brand-ver{color:var(--ink-3)}
.topbar-right{display:flex;align-items:center;gap:18px;font-family:var(--mono);font-size:12px;color:var(--ink-3)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);display:inline-block;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(200,30,59,.5)}70%{box-shadow:0 0 0 8px rgba(200,30,59,0)}100%{box-shadow:0 0 0 0 rgba(200,30,59,0)}}
.hero{display:grid;grid-template-columns:1.4fr 1fr;gap:48px;padding:8px 0 36px;border-bottom:1px solid var(--rule);margin-bottom:28px}
.hero-eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3);margin-bottom:14px}
.hero h1{font-family:var(--serif);font-size:clamp(32px,4.4vw,60px);line-height:1.02;font-weight:500;letter-spacing:-.015em;margin:0 0 18px;text-wrap:balance}
.hero h1 .accent{color:var(--accent);font-style:italic}
.hero-meta{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid var(--rule-soft);margin-top:24px;padding-top:14px}
.hero-meta dt{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);margin-bottom:4px}
.hero-meta dd{margin:0;font-family:var(--mono);font-size:13px}
.posture{background:var(--ink);color:var(--paper);padding:28px;border-radius:var(--radius);display:flex;flex-direction:column;gap:16px;position:relative;overflow:hidden}
.posture::before{content:"";position:absolute;inset:0;background:repeating-linear-gradient(135deg,transparent 0 8px,rgba(255,255,255,.02) 8px 9px);pointer-events:none}
.posture-grade{font-family:var(--serif);font-size:96px;line-height:.9;font-weight:500;color:var(--accent);letter-spacing:-.02em}
.posture-label{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:rgba(255,255,255,.5)}
.posture-counts{display:grid;grid-template-columns:repeat(5,1fr);gap:0;border-top:1px solid rgba(255,255,255,.1);padding-top:14px}
.posture-counts>div{border-right:1px solid rgba(255,255,255,.1);padding-right:8px}
.posture-counts>div:last-child{border-right:none}
.posture-count-num{font-family:var(--serif);font-size:26px;font-weight:500;line-height:1}
.posture-count-num.critical{color:var(--sev-critical-fg)}
.posture-count-num.high{color:var(--accent)}
.posture-count-num.med{color:#f3a93e}
.posture-count-num.low{color:#79a8e8}
.posture-count-label{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:rgba(255,255,255,.5);margin-top:4px}
.exec-summary{font-family:var(--serif);font-size:18px;line-height:1.55;color:var(--ink-2);max-width:70ch;text-wrap:pretty}
.exec-summary::first-letter{font-size:1.6em;font-weight:500;float:left;line-height:.9;margin:4px 8px 0 0;color:var(--accent)}
.body{display:grid;grid-template-columns:220px 1fr;gap:48px;align-items:start}
.toc{position:sticky;top:80px;font-family:var(--mono);font-size:12px}
.toc-h{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3);margin:0 0 12px;padding-bottom:8px;border-bottom:1px solid var(--rule-soft)}
.toc-list{list-style:none;margin:0 0 24px;padding:0;display:flex;flex-direction:column;gap:2px}
.toc-item{padding:6px 8px 6px 14px;cursor:pointer;border-left:2px solid transparent;color:var(--ink-3);display:flex;align-items:center;gap:8px;transition:color 120ms,border-color 120ms;overflow:hidden}
.toc-item:hover{color:var(--ink)}
.toc-item.active{color:var(--ink);border-left-color:var(--accent);background:var(--paper-2)}
.toc-item .toc-sev{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.toc-sev.critical{background:var(--sev-critical-bar)}
.toc-sev.high{background:var(--sev-high-bar)}
.toc-sev.med{background:var(--sev-med-bar)}
.toc-sev.low{background:var(--sev-low-bar)}
.tabs{display:flex;border-bottom:1px solid var(--rule);margin-bottom:24px}
.tab{background:none;border:none;padding:12px 18px 10px;font-family:var(--mono);font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;display:flex;align-items:center;gap:8px}
.tab:hover{color:var(--ink)}
.tab.active{color:var(--ink);border-bottom-color:var(--accent)}
.tab-count{background:var(--paper-2);border-radius:999px;padding:1px 7px;font-size:10px;color:var(--ink-3)}
.tab.active .tab-count{background:var(--ink);color:var(--paper)}
.toolbar{display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.search{flex:1;min-width:240px;position:relative;display:flex;align-items:center}
.search svg{position:absolute;left:12px;color:var(--ink-3)}
.search input{width:100%;background:var(--paper-2);border:1px solid var(--rule-soft);border-radius:var(--radius);padding:9px 12px 9px 36px;font-family:var(--mono);font-size:13px;color:var(--ink);outline:none;transition:border-color 120ms}
.search input:focus{border-color:var(--ink)}
.sev-filter{display:inline-flex;border:1px solid var(--rule-soft);border-radius:var(--radius);overflow:hidden}
.sev-filter button{background:var(--paper-2);border:none;border-right:1px solid var(--rule-soft);padding:9px 12px;font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;color:var(--ink-3);display:flex;align-items:center;gap:6px}
.sev-filter button:last-child{border-right:none}
.sev-filter button.active{background:var(--ink);color:var(--paper)}
.sev-filter button:not(.active):hover{color:var(--ink)}
.sev-filter .dot{width:6px;height:6px;border-radius:50%}
.sev-filter .dot.all{background:var(--ink-3)}
.sev-filter .dot.critical{background:var(--sev-critical-bar)}
.sev-filter .dot.high{background:var(--sev-high-bar)}
.sev-filter .dot.med{background:var(--sev-med-bar)}
.sev-filter .dot.low{background:var(--sev-low-bar)}
.toolbar-action{background:none;border:1px solid var(--rule-soft);border-radius:var(--radius);padding:9px 12px;font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3);cursor:pointer}
.toolbar-action:hover{color:var(--ink);border-color:var(--ink)}
.sev{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.12em;padding:4px 8px;border-radius:2px;display:inline-block}
.sev-CRITICAL{background:var(--sev-critical-bg);color:var(--sev-critical-fg)}
.sev-HIGH{background:var(--sev-high-bg);color:var(--sev-high-fg)}
.sev-MED{background:var(--sev-med-bg);color:var(--sev-med-fg)}
.sev-LOW{background:var(--sev-low-bg);color:var(--sev-low-fg)}
.findings-list{display:flex;flex-direction:column;gap:12px}
.finding{background:#fff;border:1px solid var(--rule-soft);border-radius:var(--radius);position:relative;overflow:hidden;transition:box-shadow 160ms}
.finding::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--rule-soft)}
.sev-card-CRITICAL::before{background:var(--sev-critical-bar)}
.sev-card-HIGH::before{background:var(--sev-high-bar)}
.sev-card-MED::before{background:var(--sev-med-bar)}
.sev-card-LOW::before{background:var(--sev-low-bar)}
.finding.expanded{box-shadow:var(--shadow-pop)}
.finding-head{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;padding:18px 20px 16px 24px;cursor:pointer;user-select:none}
.finding-head:hover{background:var(--paper-2)}
.finding.expanded .finding-head{background:var(--paper-2);border-bottom:1px solid var(--rule-soft)}
.finding-head-left{display:flex;gap:14px;align-items:flex-start;flex:1;min-width:0}
.finding-meta{flex:1;min-width:0}
.finding-id{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.finding-type{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.finding-title{font-family:var(--serif);font-size:22px;font-weight:500;line-height:1.25;margin:0;letter-spacing:-.005em}
.finding-head-right{display:flex;align-items:center;gap:16px}
.expand-btn{background:none;border:1px solid var(--rule-soft);border-radius:50%;width:28px;height:28px;display:grid;place-items:center;cursor:pointer;color:var(--ink-3);transition:transform 200ms;flex-shrink:0}
.finding.expanded .expand-btn{transform:rotate(180deg)}
.finding-head:hover .expand-btn{color:var(--ink);border-color:var(--ink)}
.blast{text-align:right;flex-shrink:0}
.blast-label{font-family:var(--mono);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);margin-bottom:4px}
.blast-track{display:inline-flex;align-items:center;gap:2px}
.blast-cell{width:6px;height:14px;background:var(--paper-3);border-radius:1px}
.blast-CRITICAL .blast-cell.on,.blast-high .blast-cell.on{background:var(--accent)}
.blast-med .blast-cell.on{background:var(--warn)}
.blast-low .blast-cell.on{background:var(--info)}
.blast-num{font-family:var(--mono);font-size:11px;margin-left:8px;color:var(--ink)}
.finding-body{padding:20px 24px 28px;display:grid;gap:22px;animation:fbIn 240ms ease}
@keyframes fbIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.fb-section h4.fb-h{font-family:var(--mono);font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3);margin:0 0 8px;font-weight:600}
.fb-section p{margin:0;max-width:75ch;text-wrap:pretty}
.narrative{font-family:var(--serif);font-size:17px;line-height:1.5;color:var(--ink-2);border-left:2px solid var(--accent);padding-left:16px}
.evidence{font-family:var(--mono);font-size:12.5px;background:var(--paper-2);border:1px solid var(--rule-soft);border-radius:var(--radius);padding:14px 16px;margin:0;white-space:pre-wrap;word-break:break-word;color:var(--ink-2);position:relative;line-height:1.55}
.evidence code{background:none;padding:0}
.perm-row{display:flex;gap:8px;flex-wrap:wrap}
.perm-pill{font-family:var(--mono);font-size:11px;background:var(--ink);color:var(--paper);padding:4px 10px;border-radius:2px}
.kc{list-style:none;margin:0;padding:0;position:relative}
.kc::before{content:"";position:absolute;left:14px;top:14px;bottom:14px;width:1px;background:var(--rule-soft)}
.kc-step{display:grid;grid-template-columns:30px 1fr;gap:16px;padding:6px 0;position:relative}
.kc-marker{position:relative;z-index:1}
.kc-num{width:30px;height:30px;border-radius:2px;background:var(--paper);border:1px solid var(--ink);font-family:var(--mono);font-size:11px;font-weight:600;display:grid;place-items:center;color:var(--ink)}
.sev-card-HIGH .kc-num,.sev-card-CRITICAL .kc-num{background:var(--ink);color:var(--paper)}
.kc-body{padding-top:5px;line-height:1.55;max-width:75ch;text-wrap:pretty}
.remed{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}
.remed li{display:flex;gap:12px;align-items:flex-start;max-width:75ch}
.remed-bullet{color:var(--ok);font-family:var(--mono);font-weight:700;flex-shrink:0}
.remed-teaser{font-family:var(--mono);font-size:12px;color:var(--ink-3);padding:12px 16px;background:var(--paper-2);border:1px solid var(--rule-soft);border-radius:var(--radius)}
.copy-chip{background:var(--paper-2);border:1px solid var(--rule-soft);border-radius:2px;padding:3px 8px;font-family:var(--mono);font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;color:var(--ink-2);transition:all 120ms}
.copy-chip:hover{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.copy-chip.copied{background:var(--ok);color:white;border-color:var(--ok)}
.evidence .copy-chip{position:absolute;top:8px;right:8px}
.graph-wrap{background:#fff;border:1px solid var(--rule-soft);border-radius:var(--radius);padding:24px;position:relative}
.graph-svg{width:100%;height:auto;display:block;font-family:var(--mono);font-size:11px}
.node{cursor:pointer;transition:opacity 200ms}
.node rect{fill:#fff;stroke:var(--ink);stroke-width:1;transition:all 180ms}
.node text{font-size:11px;fill:var(--ink);pointer-events:none;font-family:var(--mono)}
.node-actor rect{fill:var(--ink)}
.node-actor text{fill:var(--paper)}
.node-tool rect{fill:#fff}
.node-external rect{fill:var(--paper-2);stroke:var(--accent)}
.node-perm rect{fill:var(--ink)}
.node-perm text{fill:var(--paper);font-size:10px;letter-spacing:.06em}
.node-dim{opacity:.25}
.node-high rect{stroke-width:2}
.node-sel rect{stroke:var(--accent);stroke-width:2}
.sev-bar-CRITICAL,.sev-bar-HIGH{fill:var(--sev-high-bar)}
.sev-bar-MED{fill:var(--sev-med-bar)}
.sev-bar-LOW{fill:var(--sev-low-bar)}
.edge .edge-base{fill:none;stroke:var(--ink-3);stroke-width:1;color:var(--ink-3)}
.edge-risk .edge-base{stroke:var(--accent);stroke-width:1.4;color:var(--accent)}
.edge-flow{fill:none;stroke:var(--accent);stroke-width:2;stroke-dasharray:4 6;animation:flow 1.4s linear infinite;opacity:.85}
@keyframes flow{from{stroke-dashoffset:0}to{stroke-dashoffset:-20}}
.graph-legend{display:flex;flex-wrap:wrap;gap:18px;margin-top:16px;padding-top:16px;border-top:1px solid var(--rule-soft);font-family:var(--mono);font-size:11px;color:var(--ink-3)}
.graph-legend>div{display:flex;align-items:center;gap:6px}
.lg-dot{width:14px;height:10px;border-radius:2px;border:1px solid var(--ink)}
.lg-tool{background:#fff}
.lg-actor{background:var(--ink)}
.lg-external{background:var(--paper-2);border-color:var(--accent);border-style:dashed}
.lg-perm{background:var(--ink)}
.lg-edge{width:18px;height:0;border-top:1px solid var(--ink-3)}
.lg-edge-risk{border-top-color:var(--accent);border-top-width:1.5px}
.graph-side{display:grid;grid-template-columns:1.4fr 1fr;gap:24px;margin-top:24px}
.graph-detail{background:var(--paper-2);border:1px solid var(--rule-soft);border-radius:var(--radius);padding:20px 22px}
.graph-detail h3{font-family:var(--serif);font-size:22px;margin:0 0 8px;font-weight:500}
.graph-detail .gd-id{font-family:var(--mono);font-size:11px;color:var(--ink-3);margin-bottom:14px}
.graph-detail p{margin:0 0 12px;max-width:60ch}
.kc-deck{display:flex;flex-direction:column;gap:28px}
.kc-deck-item{background:#fff;border:1px solid var(--rule-soft);border-radius:var(--radius);padding:24px 28px;position:relative}
.kc-deck-head{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--rule-soft)}
.kc-deck-head h3{font-family:var(--serif);font-size:24px;font-weight:500;margin:8px 0 0}
.kc-deck-head .kc-id{font-family:var(--mono);font-size:11px;color:var(--ink-3)}
.footer{margin-top:60px;padding-top:24px;border-top:1px solid var(--rule);font-family:var(--mono);font-size:11px;color:var(--ink-3);display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}
.tweaks-panel-host{font-family:var(--sans)}
@media print{.topbar,.toc,.tabs,.toolbar,.tweaks-panel-host{display:none!important}.body{grid-template-columns:1fr}.app{max-width:none;padding:0 16px}.finding{box-shadow:none!important;page-break-inside:avoid;border:1px solid #ccc}.finding-body{display:grid!important}body{background:white}}
@media(max-width:960px){.hero{grid-template-columns:1fr;gap:24px}.body{grid-template-columns:1fr}.toc{position:static;margin-bottom:16px}.graph-side{grid-template-columns:1fr}.app{padding:0 20px 60px}}
"""


_TWEAKS_PANEL_JSX = r"""
const __TWEAKS_STYLE = `
  .twk-panel{position:fixed;right:16px;bottom:16px;z-index:2147483646;width:280px;
    max-height:calc(100vh - 32px);display:flex;flex-direction:column;
    background:rgba(250,249,247,.78);color:#29261b;
    -webkit-backdrop-filter:blur(24px) saturate(160%);backdrop-filter:blur(24px) saturate(160%);
    border:.5px solid rgba(255,255,255,.6);border-radius:14px;
    box-shadow:0 1px 0 rgba(255,255,255,.5) inset,0 12px 40px rgba(0,0,0,.18);
    font:11.5px/1.4 ui-sans-serif,system-ui,-apple-system,sans-serif;overflow:hidden}
  .twk-hd{display:flex;align-items:center;justify-content:space-between;
    padding:10px 8px 10px 14px;cursor:move;user-select:none}
  .twk-hd b{font-size:12px;font-weight:600}
  .twk-x{appearance:none;border:0;background:transparent;color:rgba(41,38,27,.55);
    width:22px;height:22px;border-radius:6px;cursor:default;font-size:13px;line-height:1}
  .twk-x:hover{background:rgba(0,0,0,.06);color:#29261b}
  .twk-body{padding:2px 14px 14px;display:flex;flex-direction:column;gap:10px;
    overflow-y:auto;min-height:0}
  .twk-row{display:flex;flex-direction:column;gap:5px}
  .twk-row-h{flex-direction:row;align-items:center;justify-content:space-between;gap:10px}
  .twk-lbl{display:flex;justify-content:space-between;align-items:baseline;color:rgba(41,38,27,.72)}
  .twk-lbl>span:first-child{font-weight:500}
  .twk-sect{font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
    color:rgba(41,38,27,.45);padding:10px 0 0}
  .twk-toggle{position:relative;width:32px;height:18px;border:0;border-radius:999px;
    background:rgba(0,0,0,.15);transition:background .15s;cursor:default;padding:0}
  .twk-toggle[data-on="1"]{background:#34c759}
  .twk-toggle i{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;
    background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:transform .15s}
  .twk-toggle[data-on="1"] i{transform:translateX(14px)}
  .twk-seg{position:relative;display:flex;padding:2px;border-radius:8px;
    background:rgba(0,0,0,.06);user-select:none}
  .twk-seg-thumb{position:absolute;top:2px;bottom:2px;border-radius:6px;
    background:rgba(255,255,255,.9);box-shadow:0 1px 2px rgba(0,0,0,.12);
    transition:left .15s cubic-bezier(.3,.7,.4,1),width .15s}
  .twk-seg button{appearance:none;position:relative;z-index:1;flex:1;border:0;
    background:transparent;color:inherit;font:inherit;font-weight:500;min-height:22px;
    border-radius:6px;cursor:default;padding:4px 6px;line-height:1.2}
  .twk-swatch{appearance:none;-webkit-appearance:none;width:56px;height:22px;
    border:.5px solid rgba(0,0,0,.1);border-radius:6px;padding:0;cursor:default;background:transparent;flex-shrink:0}
  .twk-swatch::-webkit-color-swatch-wrapper{padding:0}
  .twk-swatch::-webkit-color-swatch{border:0;border-radius:5.5px}
`;

function useTweaks(defaults) {
  const [values, setValues] = React.useState(defaults);
  const setTweak = React.useCallback((keyOrEdits, val) => {
    const edits = typeof keyOrEdits === 'object' && keyOrEdits !== null
      ? keyOrEdits : { [keyOrEdits]: val };
    setValues(prev => ({ ...prev, ...edits }));
  }, []);
  return [values, setTweak];
}

function TweaksPanel({ title = 'Tweaks', children }) {
  const [open, setOpen] = React.useState(false);
  const dragRef = React.useRef(null);
  const offsetRef = React.useRef({ x: 16, y: 16 });
  const PAD = 16;

  const clamp = React.useCallback(() => {
    const panel = dragRef.current;
    if (!panel) return;
    const w = panel.offsetWidth, h = panel.offsetHeight;
    offsetRef.current = {
      x: Math.min(Math.max(PAD, window.innerWidth - w - PAD), Math.max(PAD, offsetRef.current.x)),
      y: Math.min(Math.max(PAD, window.innerHeight - h - PAD), Math.max(PAD, offsetRef.current.y)),
    };
    panel.style.right = offsetRef.current.x + 'px';
    panel.style.bottom = offsetRef.current.y + 'px';
  }, []);

  React.useEffect(() => {
    if (!open) return;
    clamp();
    window.addEventListener('resize', clamp);
    return () => window.removeEventListener('resize', clamp);
  }, [open, clamp]);

  const onDragStart = (e) => {
    const panel = dragRef.current;
    if (!panel) return;
    const r = panel.getBoundingClientRect();
    const sx = e.clientX, sy = e.clientY;
    const startRight = window.innerWidth - r.right;
    const startBottom = window.innerHeight - r.bottom;
    const move = (ev) => {
      offsetRef.current = { x: startRight - (ev.clientX - sx), y: startBottom - (ev.clientY - sy) };
      clamp();
    };
    const up = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };

  if (!open) return (
    <button onClick={() => setOpen(true)}
      style={{position:'fixed',bottom:16,right:16,zIndex:2147483645,background:'var(--ink)',color:'var(--paper)',border:'none',borderRadius:8,padding:'8px 14px',fontFamily:'var(--mono)',fontSize:11,cursor:'pointer',letterSpacing:'.06em',textTransform:'uppercase'}}>
      Tweaks
    </button>
  );
  return (
    <>
      <style>{__TWEAKS_STYLE}</style>
      <div ref={dragRef} className="twk-panel" style={{right:offsetRef.current.x,bottom:offsetRef.current.y}}>
        <div className="twk-hd" onMouseDown={onDragStart}>
          <b>{title}</b>
          <button className="twk-x" onClick={() => setOpen(false)}>✕</button>
        </div>
        <div className="twk-body">{children}</div>
      </div>
    </>
  );
}

function TweakSection({ label }) { return <div className="twk-sect">{label}</div>; }
function TweakToggle({ label, value, onChange }) {
  return (
    <div className="twk-row twk-row-h">
      <div className="twk-lbl"><span>{label}</span></div>
      <button type="button" className="twk-toggle" data-on={value ? '1' : '0'}
              role="switch" aria-checked={!!value} onClick={() => onChange(!value)}><i /></button>
    </div>
  );
}
function TweakRadio({ label, value, options, onChange }) {
  const trackRef = React.useRef(null);
  const opts = options.map(o => typeof o === 'object' ? o : { value: o, label: o });
  const idx = Math.max(0, opts.findIndex(o => o.value === value));
  const n = opts.length;
  return (
    <div className="twk-row">
      <div className="twk-lbl"><span>{label}</span></div>
      <div ref={trackRef} className="twk-seg">
        <div className="twk-seg-thumb"
             style={{left:`calc(2px + ${idx} * (100% - 4px) / ${n})`,width:`calc((100% - 4px) / ${n})`}} />
        {opts.map(o => (
          <button key={o.value} type="button" onClick={() => onChange(o.value)}>{o.label}</button>
        ))}
      </div>
    </div>
  );
}
function TweakColor({ label, value, onChange }) {
  return (
    <div className="twk-row twk-row-h">
      <div className="twk-lbl"><span>{label}</span></div>
      <input type="color" className="twk-swatch" value={value} onChange={e => onChange(e.target.value)} />
    </div>
  );
}
Object.assign(window, { useTweaks, TweaksPanel, TweakSection, TweakToggle, TweakRadio, TweakColor });
"""


_GRAPH_JSX = r"""
const { useState, useEffect, useRef, useMemo } = React;

function PropagationGraph({ onSelect, selectedId }) {
  const [hover, setHover] = useState(null);
  const W = 780;
  const H = GRAPH_H;

  const nodeById = useMemo(() => {
    const m = {};
    GRAPH_NODES.forEach(n => (m[n.id] = n));
    return m;
  }, []);

  const isHighlighted = id => {
    const active = hover || selectedId;
    if (!active) return false;
    if (id === active) return true;
    return GRAPH_EDGES.some(e => (e.from === active && e.to === id) || (e.to === active && e.from === id));
  };

  const edgeActive = e => {
    const active = hover || selectedId;
    if (!active) return false;
    return e.from === active || e.to === active;
  };

  return (
    <div className="graph-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} className="graph-svg" role="img" aria-label="Propagation graph">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
          </marker>
          <marker id="arrow-risk" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#c81e3b" />
          </marker>
          <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
            <path d="M 24 0 L 0 0 0 24" fill="none" stroke="rgba(15,15,20,0.04)" strokeWidth="1" />
          </pattern>
        </defs>
        <rect width={W} height={H} fill="url(#grid)" />
        {GRAPH_EDGES.map((e, i) => {
          const a = nodeById[e.from], b = nodeById[e.to];
          if (!a || !b) return null;
          const active = edgeActive(e);
          const risky = e.risky;
          const dx = b.x - a.x, dy = b.y - a.y;
          const len = Math.hypot(dx, dy);
          const nx = dx / len, ny = dy / len;
          const padA = 56, padB = 60;
          const x1 = a.x + nx * padA, y1 = a.y + ny * padA;
          const x2 = b.x - nx * padB, y2 = b.y - ny * padB;
          const isReverse = GRAPH_EDGES.some(o => o.from === e.to && o.to === e.from);
          const cx = (x1 + x2) / 2 + (isReverse ? -ny * 18 : 0);
          const cy = (y1 + y2) / 2 + (isReverse ? nx * 18 : 0);
          const path = isReverse ? `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}` : `M ${x1} ${y1} L ${x2} ${y2}`;
          return (
            <g key={i} className={`edge ${risky ? "edge-risk" : ""} ${active ? "edge-active" : ""}`}>
              <path d={path} className="edge-base" markerEnd={risky ? "url(#arrow-risk)" : "url(#arrow)"} />
              {risky && <path d={path} className="edge-flow" />}
            </g>
          );
        })}
        {GRAPH_NODES.map(n => {
          const high = isHighlighted(n.id);
          const dim = (hover || selectedId) && !high;
          return (
            <g key={n.id}
               className={`node node-${n.kind} ${dim ? "node-dim" : ""} ${high ? "node-high" : ""} ${selectedId === n.id ? "node-sel" : ""}`}
               transform={`translate(${n.x},${n.y})`}
               onMouseEnter={() => setHover(n.id)}
               onMouseLeave={() => setHover(null)}
               onClick={() => onSelect && onSelect(n.id)}
               tabIndex={0}>
              {n.kind === "tool" && (
                <>
                  <rect x={-58} y={-22} width={116} height={44} rx={6} />
                  {n.severity && <rect x={-58} y={-22} width={4} height={44} className={`sev-bar sev-bar-${n.severity}`} />}
                </>
              )}
              {n.kind === "actor" && <rect x={-50} y={-18} width={100} height={36} rx={18} />}
              {n.kind === "external" && <rect x={-58} y={-22} width={116} height={44} rx={6} strokeDasharray="3 3" />}
              {n.kind === "perm" && <rect x={-62} y={-16} width={124} height={32} rx={4} />}
              <text textAnchor="middle" dy="4">{n.label}</text>
            </g>
          );
        })}
      </svg>
      <div className="graph-legend">
        <div><span className="lg-dot lg-tool" /> MCP tool</div>
        <div><span className="lg-dot lg-actor" /> Actor</div>
        <div><span className="lg-dot lg-external" /> External system</div>
        <div><span className="lg-dot lg-perm" /> Permission</div>
        <div><span className="lg-edge lg-edge-risk" /> Risky data flow</div>
        <div><span className="lg-edge" /> Normal call</div>
      </div>
    </div>
  );
}
window.PropagationGraph = PropagationGraph;
"""


_FINDINGS_JSX = r"""
const { useState: useStateF, useRef: useRefF } = React;

function CopyChip({ text, label }) {
  const [copied, setCopied] = useStateF(false);
  return (
    <button className={`copy-chip ${copied ? "copied" : ""}`}
            onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
            title={`Copy ${label || text}`}>
      <span className="copy-chip-text">{label || text}</span>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        {copied ? <polyline points="20 6 9 17 4 12" /> : <><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></>}
      </svg>
    </button>
  );
}

function SeverityBadge({ severity }) {
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}

function BlastRadius({ value }) {
  const cells = Array.from({ length: 10 }, (_, i) => i < value);
  const tone = value >= 7 ? "high" : value >= 4 ? "med" : "low";
  return (
    <div className={`blast blast-${tone}`} title={`Blast radius ${value}/10`}>
      <div className="blast-label">BLAST RADIUS</div>
      <div className="blast-track">
        {cells.map((on, i) => <span key={i} className={`blast-cell ${on ? "on" : ""}`} />)}
        <span className="blast-num">{value}/10</span>
      </div>
    </div>
  );
}

function KillChain({ steps }) {
  if (!steps || steps.length === 0) return null;
  return (
    <ol className="kc">
      {steps.map((s, i) => (
        <li key={i} className="kc-step">
          <div className="kc-marker"><div className="kc-num">{String(i + 1).padStart(2, "0")}</div></div>
          <div className="kc-body">{s}</div>
        </li>
      ))}
    </ol>
  );
}

function FindingCard({ f, expanded, onToggle, query, showRemediation }) {
  const highlight = text => {
    if (!query) return text;
    const q = query.trim();
    if (!q) return text;
    const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "ig");
    const parts = text.split(re);
    return parts.map((p, i) => re.test(p) ? <mark key={i}>{p}</mark> : <React.Fragment key={i}>{p}</React.Fragment>);
  };

  return (
    <article id={`finding-${f.id.replace(/[^a-z0-9]/gi, "-")}`}
             className={`finding sev-card-${f.severity} ${expanded ? "expanded" : ""}`}>
      <header className="finding-head" onClick={onToggle}>
        <div className="finding-head-left">
          <SeverityBadge severity={f.severity} />
          <div className="finding-meta">
            <div className="finding-id">
              <CopyChip text={f.id} />
              <span className="finding-type">{f.type}</span>
            </div>
            <h3 className="finding-title">{highlight(f.title)}</h3>
          </div>
        </div>
        <div className="finding-head-right">
          <BlastRadius value={f.blast_radius} />
          <button className="expand-btn" aria-label={expanded ? "Collapse" : "Expand"}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>
        </div>
      </header>
      {expanded && (
        <div className="finding-body">
          <section className="fb-section">
            <h4 className="fb-h">Description</h4>
            <p>{highlight(f.description)}</p>
          </section>
          <section className="fb-section">
            <h4 className="fb-h">Evidence</h4>
            <pre className="evidence"><code>{highlight(f.evidence)}</code><CopyChip text={f.evidence} label="copy" /></pre>
          </section>
          <section className="fb-section">
            <h4 className="fb-h">Attack narrative</h4>
            <p className="narrative">{f.narrative}</p>
          </section>
          {f.permissions && f.permissions.length > 0 && (
            <section className="fb-section">
              <h4 className="fb-h">Permissions in play</h4>
              <div className="perm-row">{f.permissions.map(p => <code key={p} className="perm-pill">{p}</code>)}</div>
            </section>
          )}
          {f.kill_chain && f.kill_chain.length > 0 && (
            <section className="fb-section">
              <h4 className="fb-h">Kill chain</h4>
              <KillChain steps={f.kill_chain} />
            </section>
          )}
          <section className="fb-section">
            <h4 className="fb-h">Remediation</h4>
            {showRemediation && f.remediation && f.remediation.length > 0 ? (
              <ul className="remed">
                {f.remediation.map((r, i) => <li key={i}><span className="remed-bullet">→</span><span>{r}</span></li>)}
              </ul>
            ) : (
              <div className="remed-teaser">Remediation guidance available in Antidote Pro.</div>
            )}
          </section>
        </div>
      )}
    </article>
  );
}

window.FindingCard = FindingCard;
window.CopyChip = CopyChip;
window.SeverityBadge = SeverityBadge;
window.BlastRadius = BlastRadius;
window.KillChain = KillChain;
"""


_APP_JSX = r"""
const { useState: useS, useEffect: useE, useMemo: useM, useRef: useR } = React;
const { KillChain, BlastRadius, SeverityBadge, FindingCard } = window;

function App() {
  const [tab, setTab] = useS("findings");
  const [sevFilter, setSevFilter] = useS("ALL");
  const [query, setQuery] = useS("");
  const [expandedIds, setExpandedIds] = useS(new Set(REPORT.findings.length ? [REPORT.findings[0].id] : []));
  const [selectedNode, setSelectedNode] = useS(REPORT.findings.length ? REPORT.findings[0].id : null);
  const [activeToc, setActiveToc] = useS(null);

  const [tweaks, setTweak] = window.useTweaks({ accent: "#c81e3b", showRemediation: false, density: "comfortable" });

  useE(() => {
    document.documentElement.style.setProperty("--accent", tweaks.accent);
    document.body.dataset.density = tweaks.density;
  }, [tweaks.accent, tweaks.density]);

  const counts = REPORT.counts;

  const grade = useM(() => {
    if (counts.critical > 0) return "F";
    if (counts.high >= 2) return "D";
    if (counts.high === 1) return "C";
    if (counts.med >= 2) return "B";
    return "A";
  }, []);

  const filtered = useM(() => REPORT.findings.filter(f => {
    if (sevFilter !== "ALL" && f.severity !== sevFilter) return false;
    if (query.trim()) {
      const q = query.toLowerCase();
      const hay = (f.id + " " + f.title + " " + f.description + " " + f.evidence + " " + f.type).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }), [sevFilter, query]);

  const toggleExpand = id => setExpandedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const expandAll = () => setExpandedIds(new Set(REPORT.findings.map(f => f.id)));
  const collapseAll = () => setExpandedIds(new Set());

  useE(() => {
    if (tab !== "findings") return;
    const handler = () => {
      const els = REPORT.findings.map(f => ({ id: f.id, el: document.getElementById(`finding-${f.id.replace(/[^a-z0-9]/gi, "-")}`) })).filter(x => x.el);
      const y = window.scrollY + 140;
      let active = null;
      for (const { id, el } of els) { if (el.offsetTop <= y) active = id; }
      setActiveToc(active);
    };
    window.addEventListener("scroll", handler);
    handler();
    return () => window.removeEventListener("scroll", handler);
  }, [tab, expandedIds]);

  const scrollToFinding = id => {
    const el = document.getElementById(`finding-${id.replace(/[^a-z0-9]/gi, "-")}`);
    if (el) { window.scrollTo({ top: el.offsetTop - 100, behavior: "smooth" }); if (!expandedIds.has(id)) toggleExpand(id); }
  };

  const selectedFinding = useM(() => REPORT.findings.find(f => f.id === selectedNode), [selectedNode]);

  const highSeverities = ["CRITICAL", "HIGH"];
  const totalHigh = REPORT.findings.filter(f => highSeverities.includes(f.severity)).length;

  return (
    <>
      <header className="topbar" style={{padding:"18px 32px 16px"}}>
        <div className="brand">
          <div className="brand-mark" />
          <span className="brand-name">Antidote</span>
          <span className="brand-sep">/</span>
          <span className="brand-ver">{REPORT.version}</span>
        </div>
        <div className="topbar-right">
          <span><span className="status-dot" />SCAN COMPLETE</span>
          <span>{new Date(REPORT.scanned_at).toISOString().replace("T"," ").slice(0,19)}Z</span>
          <button className="toolbar-action" onClick={() => window.print()}>EXPORT PDF</button>
        </div>
      </header>

      <main className="app">
        <section className="hero">
          <div>
            <div className="hero-eyebrow">MCP Security Scan / Report</div>
            <h1>
              {REPORT.target} returned{" "}
              <span className="accent">{counts.critical + counts.high} high-severity</span>{" "}
              finding{counts.critical + counts.high !== 1 ? "s" : ""}.
            </h1>
            <p className="exec-summary">{REPORT.summary}</p>
            <dl className="hero-meta">
              <div><dt>Target</dt><dd>{REPORT.target}</dd></div>
              <div><dt>Tools audited</dt><dd>{REPORT.tools_audited}</dd></div>
              <div><dt>Findings</dt><dd>{REPORT.findings.length}</dd></div>
            </dl>
          </div>
          <aside className="posture">
            <div className="posture-label">Risk Posture</div>
            <div className="posture-grade">{grade}</div>
            <div style={{fontFamily:"var(--mono)",fontSize:11,color:"rgba(255,255,255,0.65)",lineHeight:1.5}}>
              {counts.critical > 0 ? "Critical findings present. Immediate remediation required." :
               counts.high > 0 ? "High-severity findings. Remediate before untrusted client exposure." :
               "No critical or high findings. Review medium issues."}
            </div>
            <div className="posture-counts">
              <div><div className="posture-count-num critical">{counts.critical}</div><div className="posture-count-label">Critical</div></div>
              <div><div className="posture-count-num high">{counts.high}</div><div className="posture-count-label">High</div></div>
              <div><div className="posture-count-num med">{counts.med}</div><div className="posture-count-label">Med</div></div>
              <div><div className="posture-count-num low">{counts.low}</div><div className="posture-count-label">Low</div></div>
              <div><div className="posture-count-num" style={{color:"rgba(255,255,255,0.4)"}}>{counts.info}</div><div className="posture-count-label">Info</div></div>
            </div>
          </aside>
        </section>

        <nav className="tabs" role="tablist">
          <button role="tab" className={`tab ${tab === "findings" ? "active" : ""}`} onClick={() => setTab("findings")}>
            Findings <span className="tab-count">{REPORT.findings.length}</span>
          </button>
          <button role="tab" className={`tab ${tab === "graph" ? "active" : ""}`} onClick={() => setTab("graph")}>
            Propagation graph
          </button>
          <button role="tab" className={`tab ${tab === "killchains" ? "active" : ""}`} onClick={() => setTab("killchains")}>
            Kill chains <span className="tab-count">{totalHigh}</span>
          </button>
        </nav>

        {tab === "findings" && (
          <div className="body">
            <aside className="toc">
              <h4 className="toc-h">Findings</h4>
              <ul className="toc-list">
                {REPORT.findings.map(f => (
                  <li key={f.id} className={`toc-item ${activeToc === f.id ? "active" : ""}`} onClick={() => scrollToFinding(f.id)} title={f.id}>
                    <span className={`toc-sev ${f.severity.toLowerCase()}`} />
                    <span style={{overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{f.id}</span>
                  </li>
                ))}
              </ul>
              {REPORT.permissions && REPORT.permissions.length > 0 && (
                <>
                  <h4 className="toc-h">Permissions</h4>
                  <ul className="toc-list">
                    {REPORT.permissions.map(p => (
                      <li key={p} className="toc-item" style={{cursor:"default"}}>
                        <span style={{width:6,height:6,background:"var(--ink-3)",borderRadius:"50%",flexShrink:0}} />
                        <span>{p}</span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </aside>
            <div>
              <div className="toolbar">
                <div className="search">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg>
                  <input type="text" placeholder="Search findings, evidence…" value={query} onChange={e => setQuery(e.target.value)} />
                </div>
                <div className="sev-filter">
                  {[
                    { k: "ALL", l: "All", n: REPORT.findings.length, dot: "all" },
                    { k: "CRITICAL", l: "Critical", n: counts.critical, dot: "critical" },
                    { k: "HIGH", l: "High", n: counts.high, dot: "high" },
                    { k: "MED", l: "Med", n: counts.med, dot: "med" },
                    { k: "LOW", l: "Low", n: counts.low, dot: "low" },
                  ].map(b => (
                    <button key={b.k} className={sevFilter === b.k ? "active" : ""} onClick={() => setSevFilter(b.k)}>
                      <span className={`dot ${b.dot}`} />{b.l} ({b.n})
                    </button>
                  ))}
                </div>
                <button className="toolbar-action" onClick={expandAll}>Expand all</button>
                <button className="toolbar-action" onClick={collapseAll}>Collapse all</button>
              </div>
              <div className="findings-list">
                {filtered.map(f => (
                  <FindingCard key={f.id} f={f} expanded={expandedIds.has(f.id)} onToggle={() => toggleExpand(f.id)} query={query} showRemediation={tweaks.showRemediation} />
                ))}
                {filtered.length === 0 && (
                  <div style={{padding:40,textAlign:"center",color:"var(--ink-3)",fontFamily:"var(--mono)",fontSize:13}}>No findings match your filters.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === "graph" && (
          <div>
            <div style={{marginBottom:18,maxWidth:"65ch"}}>
              <p style={{fontFamily:"var(--serif)",fontSize:18,color:"var(--ink-2)",margin:0,lineHeight:1.5}}>
                Hover any node to highlight its data flows. Click a tool to see its finding details. Animated edges denote risky data paths.
              </p>
            </div>
            <PropagationGraph onSelect={setSelectedNode} selectedId={selectedNode} />
            {selectedFinding && (
              <div className="graph-side">
                <div className="graph-detail">
                  <div className="gd-id">{selectedFinding.id}</div>
                  <h3>{selectedFinding.title}</h3>
                  <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:14}}>
                    <SeverityBadge severity={selectedFinding.severity} />
                    <span style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--ink-3)"}}>{selectedFinding.type}</span>
                  </div>
                  <p>{selectedFinding.narrative}</p>
                  <div style={{display:"flex",gap:8,marginTop:12,flexWrap:"wrap"}}>
                    {selectedFinding.permissions && selectedFinding.permissions.map(p => <code key={p} className="perm-pill">{p}</code>)}
                  </div>
                </div>
                <div className="graph-detail" style={{background:"#fff"}}>
                  <h4 className="fb-h" style={{marginTop:0}}>Blast radius</h4>
                  <BlastRadius value={selectedFinding.blast_radius} />
                </div>
              </div>
            )}
          </div>
        )}

        {tab === "killchains" && (
          <div className="kc-deck">
            {REPORT.findings.filter(f => ["CRITICAL","HIGH"].includes(f.severity)).map(f => (
              <article key={f.id} className="kc-deck-item">
                <header className="kc-deck-head">
                  <div>
                    <SeverityBadge severity={f.severity} />
                    <div className="kc-id" style={{marginTop:8}}>{f.id}</div>
                    <h3>{f.title}</h3>
                  </div>
                  <BlastRadius value={f.blast_radius} />
                </header>
                <p className="narrative" style={{marginBottom:24}}>{f.narrative}</p>
                {f.kill_chain && f.kill_chain.length > 0 && (
                  <>
                    <h4 className="fb-h">Kill chain</h4>
                    <KillChain steps={f.kill_chain} />
                  </>
                )}
              </article>
            ))}
            {REPORT.findings.filter(f => ["CRITICAL","HIGH"].includes(f.severity)).length === 0 && (
              <div style={{padding:40,textAlign:"center",color:"var(--ink-3)",fontFamily:"var(--mono)",fontSize:13}}>No high or critical findings.</div>
            )}
          </div>
        )}

        <footer className="footer">
          <div>{REPORT.scanner} {REPORT.version} — Generated {new Date(REPORT.scanned_at).toUTCString()}</div>
          <div>{REPORT.findings.length} findings · {REPORT.tools_audited} tools</div>
        </footer>
      </main>

      {(() => {
        const TP = window.TweaksPanel;
        const TS = window.TweakSection;
        const TC = window.TweakColor;
        const TR = window.TweakRadio;
        const TT = window.TweakToggle;
        return (
          <TP title="Tweaks">
            <TS label="Appearance" />
            <TC label="Accent" value={tweaks.accent} onChange={v => setTweak("accent", v)} />
            <TR label="Density" value={tweaks.density} options={["compact","comfortable"]} onChange={v => setTweak("density", v)} />
            <TS label="Content" />
            <TT label="Show remediation" value={tweaks.showRemediation} onChange={v => setTweak("showRemediation", v)} />
          </TP>
        );
      })()}
    </>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
"""
