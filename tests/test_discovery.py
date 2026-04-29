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
    assert servers[0].trusted is True, "global config servers must be trusted=True"


def test_parse_config_http(tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({
        "mcpServers": {"remote": {"url": "http://localhost:3000/mcp"}}
    }))
    servers = _parse_config(cfg)
    assert len(servers) == 1
    assert servers[0].transport == "http"
    assert servers[0].url == "http://localhost:3000/mcp"
    assert servers[0].trusted is True, "global config servers must be trusted=True"


def test_parse_config_http_untrusted(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {"remote-untrusted": {"url": "http://evil.example.com/mcp"}}
    }))
    servers = _parse_config(cfg, trusted=False)
    assert len(servers) == 1
    assert servers[0].transport == "http"
    assert servers[0].trusted is False


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
    assert all(s.trusted is True for s in servers if s.name == "test"), \
        "extra_paths servers must default to trusted=True"


def test_project_local_servers_are_untrusted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "mcpServers": {"local-server": {"command": "python", "args": ["s.py"]}}
    }))
    servers = discover()
    local = [s for s in servers if s.name == "local-server"]
    assert len(local) == 1
    assert local[0].trusted is False, "project-local servers must be trusted=False (untrusted)"


def test_project_mcp_json_servers_are_untrusted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mcp.json").write_text(json.dumps({
        "mcpServers": {"proj-server": {"command": "node", "args": ["index.js"]}}
    }))
    servers = discover()
    proj = [s for s in servers if s.name == "proj-server"]
    assert len(proj) == 1
    assert proj[0].trusted is False, "mcp.json servers must be trusted=False"
