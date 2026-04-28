import json
from pathlib import Path
from mcp_scan.models import ToolFinding, PropagationPath
from mcp_scan.reporter import write_json, write_markdown


def _finding() -> ToolFinding:
    return ToolFinding(tool_id="s/tool", severity="HIGH",
                       vuln_type="injection_surface",
                       description="Has injection", evidence="Ignore previous")


def _path() -> PropagationPath:
    return PropagationPath(entry_point="s/writer", reachable_tools=["s/reader"],
                           blast_radius_score=7, control_summary="Controls filesystem",
                           kill_chain=["step1", "step2"])


def test_write_json_structure(tmp_path):
    out = tmp_path / "findings.json"
    write_json([_finding()], [_path()], out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["tool_id"] == "s/tool"
    assert data["propagation_paths"][0]["blast_radius_score"] == 7


def test_write_json_empty(tmp_path):
    out = tmp_path / "findings.json"
    write_json([], [], out)
    assert json.loads(out.read_text()) == {"findings": [], "propagation_paths": []}


def test_write_markdown_contains_finding(tmp_path):
    out = tmp_path / "report.md"
    write_markdown([_finding()], [_path()], out)
    content = out.read_text()
    assert "s/tool" in content and "HIGH" in content and "Ignore previous" in content


def test_write_markdown_contains_mermaid(tmp_path):
    out = tmp_path / "report.md"
    write_markdown([_finding()], [_path()], out)
    content = out.read_text()
    assert "```mermaid" in content and "s_writer" in content


def test_write_markdown_no_findings(tmp_path):
    out = tmp_path / "report.md"
    write_markdown([], [], out)
    assert "No vulnerabilities" in out.read_text()
