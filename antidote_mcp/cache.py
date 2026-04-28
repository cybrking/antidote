import hashlib
import json
from pathlib import Path
from .models import ToolManifest, ToolFinding

_CACHE_PATH = Path(".mcp-scan-cache.json")


def tool_hash(tool: ToolManifest) -> str:
    payload = tool.tool_id + tool.description + json.dumps(tool.input_schema, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def load_cache(path: Path = _CACHE_PATH) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache: dict, path: Path = _CACHE_PATH) -> None:
    try:
        path.write_text(json.dumps(cache, indent=2))
    except OSError:
        pass


def is_cached(cache: dict, tool: ToolManifest) -> bool:
    return tool_hash(tool) in cache


def get_cached_finding(cache: dict, tool: ToolManifest) -> ToolFinding | None:
    entry = cache.get(tool_hash(tool))
    if entry is None or not entry.get("has_finding"):
        return None
    return ToolFinding(
        tool_id=tool.tool_id,
        severity=entry["severity"],
        vuln_type=entry["vuln_type"],
        description=entry["description"],
        evidence=entry["evidence"],
    )


def cache_finding(cache: dict, tool: ToolManifest, finding: ToolFinding | None) -> None:
    if finding is None:
        cache[tool_hash(tool)] = {"has_finding": False}
    else:
        cache[tool_hash(tool)] = {
            "has_finding": True,
            "severity": finding.severity,
            "vuln_type": finding.vuln_type,
            "description": finding.description,
            "evidence": finding.evidence,
        }
