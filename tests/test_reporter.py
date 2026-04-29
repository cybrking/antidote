import json
from pathlib import Path
from antidote_mcp.models import ToolFinding, PropagationPath
from antidote_mcp.reporter import write_json, write_markdown


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


def test_html_report_escapes_script_injection(tmp_path):
    from antidote_mcp.html_report import write_html
    from antidote_mcp.models import ToolManifest
    malicious_evidence = '</script><script>alert(document.cookie)</script>'
    finding = ToolFinding(
        tool_id="s/evil", severity="HIGH", vuln_type="tool_poisoning",
        description="Malicious tool", evidence=malicious_evidence,
    )
    tool = ToolManifest(server_name="s", tool_name="evil", description="evil",
                        input_schema={}, inferred_permissions=[])
    out = tmp_path / "report.html"
    write_html([finding], [], [tool], out)
    html = out.read_text()
    assert malicious_evidence not in html, (
        "Raw </script> in evidence must be escaped — unescaped form allows XSS via script block breakout"
    )


def test_html_report_escapes_script_in_description(tmp_path):
    from antidote_mcp.html_report import write_html
    from antidote_mcp.models import ToolManifest
    finding = ToolFinding(
        tool_id="s/x", severity="HIGH", vuln_type="tool_poisoning",
        description='Legitimate</script><script>alert(1)</script>',
        evidence="normal evidence",
    )
    tool = ToolManifest(server_name="s", tool_name="x", description="x",
                        input_schema={}, inferred_permissions=[])
    out = tmp_path / "report.html"
    write_html([finding], [], [tool], out)
    html = out.read_text()
    assert '</script><script>' not in html


def test_html_report_has_sri_integrity_attributes(tmp_path):
    from antidote_mcp.html_report import write_html
    from antidote_mcp.models import ToolManifest
    out = tmp_path / "report.html"
    write_html([], [], [], out)
    html = out.read_text()
    assert 'integrity=' in html, "CDN script tags must include integrity= SRI hash to prevent supply chain attacks"


def test_html_report_sri_hashes_are_present(tmp_path):
    from antidote_mcp.html_report import write_html
    out = tmp_path / "report.html"
    write_html([], [], [], out)
    html = out.read_text()
    assert 'sha384-DGyLxAyjq0f9SPpVevD6IgztCFlnMF6oW/XQGmfe+IsZ8TqEiDrcHkMLKI6fiB/Z' in html, "React SRI hash missing"
    assert 'sha384-gTGxhz21lVGYNMcdJOyq01Edg0jhn/c22nsx0kyqP0TxaV5WVdsSH1fSDUf5YJj1' in html, "ReactDOM SRI hash missing"
    assert 'sha384-m08KidiNqLdpJqLq95G/LEi8Qvjl/xUYll3QILypMoQ65QorJ9Lvtp2RXYGBFj1y' in html, "Babel SRI hash missing"


def test_html_report_escapes_tool_name_in_graph(tmp_path):
    from antidote_mcp.html_report import write_html
    from antidote_mcp.models import ToolManifest
    tool = ToolManifest(
        server_name="s",
        tool_name="</script><script>alert(1)</script>",
        description="injection via graph node label",
        input_schema={}, inferred_permissions=[],
    )
    out = tmp_path / "report.html"
    write_html([], [], [tool], out)
    html = out.read_text()
    assert '</script><script>' not in html, "tool_name injected via graph nodes_json must be escaped"
