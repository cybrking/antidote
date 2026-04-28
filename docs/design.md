# MCP Security Analyzer — Design Spec

**Date:** 2026-04-27
**Project:** mcp-scan
**Approach:** Static analysis + propagation graph (Approach 2)

---

## Problem

MCP (Model Context Protocol) servers are a new and largely unsecured attack surface. 43% of public MCP servers are vulnerable to command execution. Two attack classes with no existing tooling:

1. **Tool poisoning / injection surface** — malicious instructions embedded in tool descriptions manipulate agent behavior
2. **Parasitic toolchain attacks** — a compromised tool propagates control through chained tools downstream

No tool exists to detect either. This builds the first one.

---

## What It Does

Discovers your local MCP configuration, parses every tool manifest, builds a dependency graph of how tools chain together, runs two Claude analysis passes (per-tool vulnerability scan + propagation blast radius simulation), and outputs a security report.

**One sentence:** Point it at your Claude Desktop config, get back a findings report showing what's vulnerable and what an attacker controls if they exploit it.

---

## Architecture

```text
Discovery → Parser → Graph Builder → Claude Analysis (2 passes) → Report
```

### Stage 1 — Discovery

Locates MCP configs automatically:

- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `.claude/settings.json` in current project
- `mcp.json` files in current directory tree
- Running servers at `/.well-known/mcp.json`

### Stage 2 — Parser

Extracts from each server: tool name, description, input schema, inferred permissions.
Uses MCP Python SDK for live servers; falls back to static config parsing if server isn't running.

**Permission inference:** scan `input_schema` for properties whose names or descriptions contain keywords (`file`, `path`, `exec`, `command`, `write`, `delete`, `network`, `url`, `env`, `secret`, `key`, `token`). Each matched keyword maps to a permission label (e.g. `filesystem.read`, `filesystem.write`, `network.outbound`, `secrets.read`). Explicit keyword list, documented in code — no heuristic interpretation.

### Stage 3 — Graph Builder

Builds `nx.DiGraph` where nodes are tools and edges are inferred dependencies:

- `shared_resource` — same file path / env var appears in multiple tool schemas
- `description_ref` — one tool description references another tool by name
- `permission_overlap` — overlapping permission scopes across tools

### Stage 4 — Claude Analysis

**Pass 1 — Per-tool vulnerability scan (one API call per tool):**

Each tool sent individually with name, description, schema, inferred permissions.
Claude returns structured JSON finding.

Checks:

- Injection surface: can the description inject instructions into an agent?
- Permission scope: are permissions proportionate to stated purpose?
- Tool poisoning risk: how easily could the description be manipulated?
- Description anomalies: hidden instructions, Unicode tricks, overly broad capabilities

**Pass 2 — Propagation simulation (one API call per HIGH or CRITICAL tool):**

Triggered only for tools where Pass 1 returns severity `HIGH` or `CRITICAL`. Each qualifying tool is sent with its full graph neighborhood — the compromised tool plus all reachable downstream tools with their descriptions and permissions. Claude reasons over the subgraph and returns a blast radius assessment.

### Stage 5 — Report

- Terminal: `rich` table, severity-colored
- `findings.json` — machine-readable, CI-friendly
- `report.md` — human-readable with embedded Mermaid propagation graph

---

## Data Structures

```python
MCPServer(
    name: str,
    source: Path,
    transport: "stdio" | "http",
    command: str | None,
    url: str | None
)

ToolManifest(
    server_name: str,
    tool_name: str,
    description: str,
    input_schema: dict,
    inferred_permissions: list[str]
)

ToolFinding(
    tool_id: str,                    # "server_name/tool_name"
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    vuln_type: "injection_surface" | "permission_scope" |
               "tool_poisoning" | "description_anomaly",
    description: str,
    evidence: str                    # exact text that triggered the finding
)

PropagationPath(
    entry_point: str,
    reachable_tools: list[str],
    blast_radius_score: int,         # 1-10
    control_summary: str,
    kill_chain: list[str]
)
```

---

## File Structure

```text
mcp-scan/
├── mcp_scan/
│   ├── discovery.py    # locate config files
│   ├── parser.py       # extract tool manifests + permission inference
│   ├── graph.py        # build dependency graph + edge inference
│   ├── analyzer.py     # Claude analysis passes
│   ├── reporter.py     # format output
│   └── main.py         # orchestrate pipeline
├── tests/
│   ├── fixtures/
│   │   ├── clean_config.json
│   │   ├── injection_config.json
│   │   ├── permission_config.json
│   │   ├── chained_config.json
│   │   └── malformed_config.json
│   ├── test_parser.py
│   ├── test_graph.py
│   └── test_integration.py
└── pyproject.toml
```

---

## Stack

| Dependency | Purpose |
|---|---|
| `anthropic` | Claude API for both analysis passes |
| `networkx` | Dependency graph construction and traversal |
| `mcp` | MCP Python SDK for querying live servers |
| `rich` | Terminal output formatting |
| Python stdlib | `json`, `pathlib`, `re` |

---

## Error Handling

| Failure | Behavior |
|---|---|
| MCP server not running | Fall back to static config, note in report |
| Malformed tool manifest | Skip tool, log warning, continue |
| Claude API error | Retry once, mark finding as "analysis failed", continue |
| No config found | Clear error listing all paths checked |

No silent failures. Every skipped tool appears in the report.

---

## Testing Strategy

Unit tests against fixtures — no Claude calls, no live servers:

1. **Parser tests** — fixture JSON → assert correct `ToolManifest` objects
2. **Graph tests** — known manifests → assert correct edges inferred
3. **Integration tests** — `chained_config.json` + mocked Claude → assert correct `PropagationPath`

Claude calls mocked in all automated tests. Real Claude runs manually against actual config.

---

## Success Criteria

Given fixture configs:

1. Tool with hidden instruction in description → flagged `injection_surface HIGH`
2. Tool with filesystem write for stated read-only purpose → flagged `permission_scope MEDIUM`
3. Compromised file-access tool → propagation path identifies all downstream tools sharing that path
4. Malformed config → graceful degradation, no crash, warning in report
5. Mermaid diagram correctly renders the tool chain graph

---

## Out of Scope (v1)

- Dynamic exploitation / sandboxed probing (v2)
- CI/CD GitHub Action wrapper (v2)
- Standalone CLI binary / PyPI packaging (v2)
- Remediation suggestions (v2)
