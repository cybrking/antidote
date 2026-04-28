import json
import platform
from pathlib import Path
from .models import MCPServer

_CLAUDE_DESKTOP_PATHS = {
    "darwin": Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    "windows": Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    "linux": Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
}

_PROJECT_CONFIG_NAMES = [
    Path(".claude") / "settings.json",
    Path("mcp.json"),
]


def discover(extra_paths: list[Path] | None = None) -> list[MCPServer]:
    config_paths: list[Path] = []
    system = platform.system().lower()
    desktop = _CLAUDE_DESKTOP_PATHS.get(system)
    if desktop and desktop.exists():
        config_paths.append(desktop)
    for name in _PROJECT_CONFIG_NAMES:
        p = Path.cwd() / name
        if p.exists():
            config_paths.append(p)
    if extra_paths:
        config_paths.extend(p for p in extra_paths if p.exists())
    servers: list[MCPServer] = []
    for path in config_paths:
        servers.extend(_parse_config(path))
    return servers


def _parse_config(path: Path) -> list[MCPServer]:
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    mcp_servers = data.get("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        return []
    servers: list[MCPServer] = []
    for name, config in mcp_servers.items():
        if not isinstance(config, dict):
            continue
        if "url" in config:
            servers.append(MCPServer(name=name, source=path, transport="http", url=config["url"]))
        elif "command" in config:
            servers.append(MCPServer(
                name=name, source=path, transport="stdio",
                command=config["command"],
                args=config.get("args", []),
                env=config.get("env", {}),
            ))
    return servers
