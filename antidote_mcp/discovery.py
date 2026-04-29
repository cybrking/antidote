import json
import platform
from pathlib import Path
from .models import MCPServer

_CLAUDE_DESKTOP_PATHS = {
    "darwin": Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    "windows": Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    "linux": Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
}

_CLAUDE_CODE_PATHS = [
    Path.home() / ".claude" / "claude_desktop_config.json",
]

_PROJECT_CONFIG_NAMES = [
    Path(".claude") / "settings.json",
    Path("mcp.json"),
]


def discover(extra_paths: list[Path] | None = None) -> list[MCPServer]:
    trusted_paths: list[Path] = []
    project_paths: list[Path] = []

    system = platform.system().lower()
    desktop = _CLAUDE_DESKTOP_PATHS.get(system)
    if desktop and desktop.exists():
        trusted_paths.append(desktop)
    for p in _CLAUDE_CODE_PATHS:
        if p.exists() and p not in trusted_paths:
            trusted_paths.append(p)
    for name in _PROJECT_CONFIG_NAMES:
        p = Path.cwd() / name
        if p.exists():
            project_paths.append(p)
    if extra_paths:
        trusted_paths.extend(p for p in extra_paths if p.exists())

    servers: list[MCPServer] = []
    for path in trusted_paths:
        servers.extend(_parse_config(path, trusted=True))
    for path in project_paths:
        servers.extend(_parse_config(path, trusted=False))
    return servers


def _parse_config(path: Path, trusted: bool = True) -> list[MCPServer]:
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
            servers.append(MCPServer(name=name, source=path, transport="http",
                                     url=config["url"], trusted=trusted))
        elif "command" in config:
            servers.append(MCPServer(
                name=name, source=path, transport="stdio",
                command=config["command"],
                args=config.get("args", []),
                env=config.get("env", {}),
                trusted=trusted,
            ))
    return servers
