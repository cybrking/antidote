import asyncio
import json
from .models import MCPServer, ToolManifest

_PERMISSION_KEYWORDS: dict[str, str] = {
    "file": "filesystem.read",
    "path": "filesystem.read",
    "write": "filesystem.write",
    "delete": "filesystem.write",
    "command": "process.run",
    "network": "network.outbound",
    "url": "network.outbound",
    "http": "network.outbound",
    "env": "environment.read",
    "secret": "secrets.read",
    "key": "secrets.read",
    "token": "secrets.read",
    "password": "secrets.read",
}


def _infer_permissions(input_schema: dict) -> list[str]:
    schema_text = json.dumps(input_schema).lower()
    found: set[str] = set()
    for keyword, permission in _PERMISSION_KEYWORDS.items():
        if keyword in schema_text:
            found.add(permission)
    return sorted(found)


async def fetch_all_tools(servers: list[MCPServer]) -> list[ToolManifest]:
    tasks = [
        _fetch_tools_stdio(s) if s.transport == "stdio" else _fetch_tools_http(s)
        for s in servers
    ]
    results = await asyncio.gather(*tasks)
    return [tool for batch in results for tool in batch]


async def _fetch_tools_stdio(server: MCPServer) -> list[ToolManifest]:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        params = StdioServerParameters(
            command=server.command, args=server.args, env=server.env or None
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                return [
                    ToolManifest(
                        server_name=server.name,
                        tool_name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.inputSchema or {},
                        inferred_permissions=_infer_permissions(tool.inputSchema or {}),
                    )
                    for tool in result.tools
                ]
    except Exception:
        return []


async def _fetch_tools_http(server: MCPServer) -> list[ToolManifest]:
    try:
        from mcp import ClientSession
        from mcp.client.sse import sse_client
        async with sse_client(server.url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                return [
                    ToolManifest(
                        server_name=server.name,
                        tool_name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.inputSchema or {},
                        inferred_permissions=_infer_permissions(tool.inputSchema or {}),
                    )
                    for tool in result.tools
                ]
    except Exception:
        return []
