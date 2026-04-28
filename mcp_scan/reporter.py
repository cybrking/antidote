import json
from dataclasses import asdict
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from .models import ToolFinding, PropagationPath

_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_COLORS = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "blue"}


def print_findings(findings: list[ToolFinding], paths: list[PropagationPath]) -> None:
    console = Console()
    if not findings:
        console.print("[green]No vulnerabilities found.[/green]")
        return
    table = Table(box=box.ROUNDED, header_style="bold")
    table.add_column("Severity")
    table.add_column("Tool")
    table.add_column("Type")
    table.add_column("Evidence")
    for f in sorted(findings, key=lambda x: _ORDER.index(x.severity)):
        c = _COLORS[f.severity]
        ev = f.evidence[:60] + "..." if len(f.evidence) > 60 else f.evidence
        table.add_row(f"[{c}]{f.severity}[/{c}]", f.tool_id, f.vuln_type, ev)
    console.print(table)
    if paths:
        console.print("\n[bold]Propagation Paths:[/bold]")
        for p in paths:
            console.print(f"  [orange3]{p.entry_point}[/orange3] score {p.blast_radius_score}/10")
            console.print(f"  {p.control_summary}")


def write_json(findings: list[ToolFinding], paths: list[PropagationPath], output: Path) -> None:
    output.write_text(json.dumps(
        {"findings": [asdict(f) for f in findings],
         "propagation_paths": [asdict(p) for p in paths]},
        indent=2
    ))


def write_markdown(findings: list[ToolFinding], paths: list[PropagationPath], output: Path) -> None:
    lines = ["# MCP Security Scan Report\n"]
    if not findings:
        lines.append("No vulnerabilities found.\n")
    else:
        lines.append("## Findings\n")
        for f in sorted(findings, key=lambda x: _ORDER.index(x.severity)):
            lines += [f"### {f.severity}: {f.tool_id}",
                      f"**Type:** {f.vuln_type}",
                      f"**Description:** {f.description}",
                      f"**Evidence:** `{f.evidence}`\n"]
    if paths:
        lines += ["## Propagation Graph\n", "```mermaid", "graph TD"]
        for p in paths:
            en = p.entry_point.replace("/", "_")
            for d in p.reachable_tools:
                lines.append(f"  {en} --> {d.replace('/', '_')}")
        lines.append("```\n")
        for p in paths:
            lines += [f"### {p.entry_point} (blast radius: {p.blast_radius_score}/10)",
                      p.control_summary + "\n", "**Kill chain:**"]
            for i, step in enumerate(p.kill_chain, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
    output.write_text("\n".join(lines))
