# Antidote

**Security scanner for MCP tool servers.**

MCP (Model Context Protocol) lets AI agents call external tools. Those tools can be poisoned: injected with instructions that hijack the agent, exfiltrate data, or pivot through your toolchain. Antidote finds that before it finds you.

---

## What it catches

**Tool poisoning**: malicious instructions embedded in tool descriptions that redirect AI agents at runtime. The attack is invisible to users and bypasses normal input validation because it targets the model's context, not the application layer.

**Injection surfaces**: unconstrained string parameters paired with dangerous permissions (filesystem, network, secrets). A `url: string` field on a tool with `network.outbound` is an open exfiltration channel.

**Propagation paths**: when a compromised tool calls other tools, the blast radius multiplies. Antidote maps the dependency graph and simulates what an attacker actually gains from each entry point.

**Permission scope violations**: tools claiming capabilities inconsistent with their stated purpose.

---

## Install

```bash
pip install antidote-mcp
```

Requires Python 3.11+ and an `ANTHROPIC_API_KEY`.

---

## Usage

```bash
export ANTHROPIC_API_KEY=sk-ant-...
antidote
```

Antidote auto-discovers MCP configs from:

- `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop)
- `~/.claude/claude_desktop_config.json` (Claude Code)
- `.claude/settings.json` and `mcp.json` in the current directory

Output: terminal findings table + `findings.json` + `report.md` + `report.html` (interactive).

---

## Report

Antidote generates a self-contained `report.html` with three tabs: Findings, Propagation Graph, and Kill Chains.

**Findings** — severity-rated cards with type, evidence, and blast radius score.

![Findings tab](docs/screenshot-findings.png)

**Propagation graph** — animated SVG showing how a compromised tool reaches downstream tools and resources.

![Propagation graph tab](docs/screenshot-graph.png)

**Kill chains** — step-by-step attacker simulation for every high-risk entry point.

![Kill chains tab](docs/screenshot-killchains.png)

---

## How it works

Two-pass analysis, both deterministic (`temperature=0`):

### Pass 1: per-tool scan (Claude Haiku)

Every tool's ID, description, and input schema is analyzed against four vulnerability classes. Findings are severity-rated CRITICAL / HIGH / MEDIUM / LOW using a fixed rubric, not model judgment.

Results are cached by SHA-256 hash of the tool definition. Re-running against unchanged servers costs zero API calls.

### Pass 2: propagation analysis (Claude Sonnet)

HIGH and CRITICAL tools become the entry points for a graph traversal. Antidote builds a directed dependency graph using three edge types:

- `shared_resource`: tools operating on the same resource
- `description_ref`: tool A's description names tool B
- `permission_overlap`: tools sharing sensitive permissions

For each entry point, Sonnet simulates attacker control and scores blast radius on a 1–10 scale with a plain-English kill chain.

---

## Requirements

- Python 3.11+
- `ANTHROPIC_API_KEY` — Pass 1 uses Haiku, Pass 2 uses Sonnet. A full scan of 10 tools costs under $0.05.
- MCP servers must be reachable (stdio servers are spawned locally; HTTP servers must be running)

---

## Roadmap

- [ ] CLI flags (`--path`, `--severity`, `--json-only`)
- [ ] Exit codes for CI integration
- [ ] Coverage for Cursor, Windsurf, Cline, Zed configs
- [ ] Remediation guidance (paid tier)

---

## License

MIT
