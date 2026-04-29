import asyncio
import os
from pathlib import Path
import anthropic
from rich.console import Console
from rich.markup import escape as rich_escape
from .discovery import discover
from .parser import fetch_all_tools
from .graph import build_graph, get_reachable_tools
from .analyzer import analyze_tool, analyze_propagation
from .reporter import print_findings, write_json, write_markdown, write_html
from .cache import load_cache, save_cache, get_cached_finding, cache_finding, is_cached


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Antidote MCP Security Analyzer")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompt for project-local server commands")
    args = parser.parse_args()
    asyncio.run(_run(auto_confirm=args.yes))


async def _run(auto_confirm: bool = False) -> None:
    console = Console()
    console.print("[bold]MCP Security Analyzer[/bold]")
    servers = discover()
    untrusted = [s for s in servers if not s.trusted]
    if untrusted and not auto_confirm:
        console.print("\n[yellow]Warning: project-local MCP servers found:[/yellow]")
        for s in untrusted:
            if s.transport == "stdio":
                label = " ".join([s.command or ""] + (s.args or []))
            else:
                label = s.url or ""
            console.print(f"  [dim]{rich_escape(s.name)}:[/dim] {rich_escape(label)}")
        console.print("\nThese servers will be connected to. Run with [bold]--yes[/bold] to proceed.")
        servers = [s for s in servers if s not in untrusted]
        if not servers:
            console.print("[yellow]No trusted servers to scan. Exiting.[/yellow]")
            return
    if not servers:
        console.print("[yellow]No MCP servers found.[/yellow]")
        console.print("  Checked: ~/Library/Application Support/Claude/claude_desktop_config.json")
        console.print("           .claude/settings.json  |  mcp.json")
        return
    console.print(f"Found {len(servers)} server(s). Fetching tools...")
    tools = await fetch_all_tools(servers)
    if not tools:
        console.print("[yellow]No tools discovered. Are MCP servers running?[/yellow]")
        return
    console.print(f"Discovered {len(tools)} tool(s). Building graph...")
    graph = build_graph(tools)
    tool_map = {t.tool_id: t for t in tools}
    console.print("Pass 1: vulnerability scan...")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]Error: ANTHROPIC_API_KEY environment variable not set.[/red]")
        return
    client = anthropic.Anthropic(api_key=api_key)
    cache = load_cache()
    findings = []
    cache_hits = 0
    for t in tools:
        if is_cached(cache, t):
            finding = get_cached_finding(cache, t)
            cache_hits += 1
        else:
            finding = analyze_tool(client, t)
            cache_finding(cache, t, finding)
        if finding is not None:
            findings.append(finding)
    save_cache(cache)
    if cache_hits:
        console.print(f"  {cache_hits} tool(s) loaded from cache.")
    high_risk = {f.tool_id for f in findings if f.severity in ("HIGH", "CRITICAL")}
    paths = []
    if high_risk:
        console.print(f"Pass 2: propagation analysis for {len(high_risk)} high-risk tool(s)...")
        for tid in high_risk:
            downstream = [tool_map[r] for r in get_reachable_tools(graph, tid) if r in tool_map]
            if tid in tool_map:
                result = analyze_propagation(client, tool_map[tid], downstream)
                if result is not None:
                    paths.append(result)
    print_findings(findings, paths)
    write_json(findings, paths, Path("findings.json"))
    write_markdown(findings, paths, Path("report.md"))
    write_html(findings, paths, tools, Path("report.html"))
    console.print("\n[green]Wrote findings.json, report.md, report.html[/green]")


if __name__ == "__main__":
    main()
