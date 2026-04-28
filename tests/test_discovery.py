import json
from pathlib import Path
from antidote_mcp.discovery import discover, _parse_config


def test_parse_config_stdio(tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                "env": {"DEBUG": "1"}
            }
        }
    }))
    servers = _parse_config(cfg)
    assert len(servers) == 1
    assert servers[0].name == "filesystem"
    assert servers[0].transport == "stdio"
    assert servers[0].command == "npx"
    assert servers[0].env == {"DEBUG": "1"}


def test_parse_config_http(tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({
        "mcpServers": {"remote": {"url": "http://localhost:3000/mcp"}}
    }))
    servers = _parse_config(cfg)
    assert len(servers) == 1
    assert servers[0].transport == "http"
    assert servers[0].url == "http://localhost:3000/mcp"


def test_parse_config_malformed(tmp_path):
    cfg = tmp_path / "bad.json"
    cfg.write_text('{"mcpServers": {"broken": "not-an-object"}}')
    assert _parse_config(cfg) == []


def test_parse_config_missing_file(tmp_path):
    assert _parse_config(tmp_path / "nonexistent.json") == []


def test_discover_finds_extra_paths(tmp_path):
    cfg = tmp_path / "my_mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {"test": {"command": "python", "args": ["s.py"], "env": {}}}
    }))
    servers = discover(extra_paths=[cfg])
    assert any(s.name == "test" for s in servers)
