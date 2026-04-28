import asyncio
import os
from pathlib import Path
import anthropic
from rich.console import Console
from .discovery import discover
from .parser import fetch_all_tools
from .graph import build_graph, get_reachable_tools
from .analyzer import analyze_tool, analyze_propagation
from .reporter import print_findings, write_json, write_markdown


def main() -> None:
    asyncio.run(_run())


async def _run() -> None:
    console = Console()
    console.print("[bold]MCP Security Analyzer[/bold]")
    servers = discover()
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
    findings = [f for t in tools if (f := analyze_tool(client, t)) is not None]
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
    console.print("\n[green]Wrote findings.json and report.md[/green]")


if __name__ == "__main__":
    main()
