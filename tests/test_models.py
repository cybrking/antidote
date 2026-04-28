from mcp_scan.models import MCPServer, ToolManifest, ToolFinding, PropagationPath
from pathlib import Path


def test_mcp_server_defaults():
    s = MCPServer(name="test", source=Path("/tmp/cfg.json"), transport="stdio")
    assert s.command is None
    assert s.args == []
    assert s.env == {}
    assert s.url is None


def test_tool_manifest_tool_id():
    t = ToolManifest(
        server_name="fs", tool_name="read_file",
        description="Reads a file", input_schema={},
    )
    assert t.tool_id == "fs/read_file"
    assert t.inferred_permissions == []


def test_tool_finding_fields():
    f = ToolFinding(
        tool_id="fs/read_file", severity="HIGH",
        vuln_type="injection_surface",
        description="Has injection", evidence="Ignore previous",
    )
    assert f.tool_id == "fs/read_file"


def test_propagation_path_fields():
    p = PropagationPath(
        entry_point="fs/write_file",
        reachable_tools=["db/query"],
        blast_radius_score=8,
        control_summary="Controls filesystem and database",
        kill_chain=["compromise write_file", "pivot to db/query"],
    )
    assert p.blast_radius_score == 8
