from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MCPServer:
    name: str
    source: Path
    transport: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None


@dataclass
class ToolManifest:
    server_name: str
    tool_name: str
    description: str
    input_schema: dict
    inferred_permissions: list[str] = field(default_factory=list)

    @property
    def tool_id(self) -> str:
        return f"{self.server_name}/{self.tool_name}"


@dataclass
class ToolFinding:
    tool_id: str
    severity: str
    vuln_type: str
    description: str
    evidence: str


@dataclass
class PropagationPath:
    entry_point: str
    reachable_tools: list[str]
    blast_radius_score: int
    control_summary: str
    kill_chain: list[str]
