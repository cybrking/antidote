import pytest
from unittest.mock import AsyncMock, patch
from pathlib import Path
from mcp_scan.models import MCPServer
from mcp_scan.parser import _infer_permissions, fetch_all_tools


def test_infer_permissions_filesystem_read():
    schema = {"properties": {"path": {"type": "string", "description": "File path to read"}}}
    assert "filesystem.read" in _infer_permissions(schema)


def test_infer_permissions_write_and_run():
    schema = {"properties": {"write": {"type": "boolean"}, "command": {"type": "string"}}}
    perms = _infer_permissions(schema)
    assert "filesystem.write" in perms
    assert "process.run" in perms


def test_infer_permissions_secrets():
    schema = {"properties": {"token": {"type": "string"}, "api_key": {"type": "string"}}}
    assert "secrets.read" in _infer_permissions(schema)


def test_infer_permissions_clean():
    schema = {"properties": {"name": {"type": "string"}, "count": {"type": "integer"}}}
    assert _infer_permissions(schema) == []


@pytest.mark.asyncio
async def test_fetch_all_tools_server_offline():
    server = MCPServer(
        name="offline", source=Path("/tmp/cfg.json"),
        transport="stdio", command="nonexistent_cmd", args=[]
    )
    with patch("mcp_scan.parser._fetch_tools_stdio", new_callable=AsyncMock, return_value=[]):
        tools = await fetch_all_tools([server])
    assert tools == []
