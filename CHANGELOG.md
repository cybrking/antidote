# Changelog

## [0.2.0] - 2026-04-29

### Security

- **Prompt injection hardening** — system and user prompts now passed as separate `system=` and `messages=` parameters to the Anthropic API, preventing attacker-controlled tool descriptions from escaping the user turn
- **XSS prevention in HTML report** — all `</script>` sequences in tool evidence, descriptions, and graph node labels are escaped before embedding in the report JSON island
- **Spawn gate for untrusted servers** — project-local MCP servers (`mcp.json`, `.claude/settings.json`) are flagged `trusted=False` and blocked from being fetched/spawned unless `--yes` is passed; applies to both stdio and HTTP transports
- **Rich markup injection fix** — server names and commands in the untrusted-server warning are escaped via `rich.markup.escape()` before interpolation into Rich console markup
- **SRI integrity hashes** — all three CDN script tags (React, ReactDOM, Babel) include `integrity=` and `crossorigin=anonymous` attributes
- **Dependency lockfile** — `uv.lock` added to pin transitive dependencies and prevent supply-chain drift

### Changed

- `_VALID_SEVERITIES` moved from inside the `try` block to module scope in `analyzer.py`
- Untrusted server warning message updated to cover HTTP endpoints (previously only showed stdio commands)

### Tests

- Added 8 new tests: trust flag assertions on existing discovery tests, HTTP bypass coverage, Rich markup injection path, trusted-server bypass gate, spawn-with-auto-confirm for HTTP

## [0.1.0] - 2026-04-28

### Added

- Initial release: two-pass MCP security analyzer (vulnerability scan + propagation analysis)
- SHA-256 cache keyed on tool content hash
- HTML report with Mermaid attack graph, Markdown report, JSON findings
- Discovery for `claude_desktop_config.json`, `.claude/settings.json`, `mcp.json`
