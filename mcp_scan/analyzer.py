import json
import anthropic
from .models import ToolManifest, ToolFinding, PropagationPath

_VULN_TEMPLATE = """\
You are a security analyst reviewing an MCP tool definition.

Tool ID: {tool_id}
Description: {description}
Input Schema: {schema}
Inferred Permissions: {permissions}

Check for one of: injection_surface, permission_scope, tool_poisoning, description_anomaly.

JSON only — no markdown:
{{"has_finding": true, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "vuln_type": "...", \
"description": "one sentence", "evidence": "exact triggering text"}}

If no issues: {{"has_finding": false}}"""

_PROPAGATION_TEMPLATE = """\
You are simulating an attacker who has compromised an MCP tool.

Compromised: {entry_point}
Description: {entry_description}
Permissions: {entry_permissions}

Reachable downstream tools:
{downstream}

What does the attacker gain? JSON only — no markdown:
{{"blast_radius_score": <1-10>, "control_summary": "plain English", "kill_chain": ["step1", "step2"]}}"""


def _build_vuln_prompt(tool: ToolManifest) -> str:
    return _VULN_TEMPLATE.format(
        tool_id=tool.tool_id,
        description=tool.description,
        schema=json.dumps(tool.input_schema, indent=2),
        permissions=tool.inferred_permissions,
    )


def analyze_tool(client: anthropic.Anthropic, tool: ToolManifest) -> ToolFinding | None:
    prompt = _build_vuln_prompt(tool)
    for attempt in range(2):
        try:
            response = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            result = json.loads(response.content[0].text)
            if not result.get("has_finding"):
                return None
            return ToolFinding(
                tool_id=tool.tool_id,
                severity=result["severity"],
                vuln_type=result["vuln_type"],
                description=result["description"],
                evidence=result["evidence"],
            )
        except Exception:
            if attempt == 1:
                return ToolFinding(
                    tool_id=tool.tool_id, severity="LOW",
                    vuln_type="description_anomaly",
                    description="Analysis failed",
                    evidence="Claude API error after 2 attempts",
                )
    return None


def analyze_propagation(
    client: anthropic.Anthropic,
    entry: ToolManifest,
    downstream: list[ToolManifest],
) -> PropagationPath:
    downstream_text = "\n".join(
        f"- {t.tool_id}: {t.description[:120]} (permissions: {t.inferred_permissions})"
        for t in downstream
    ) or "None"
    prompt = _PROPAGATION_TEMPLATE.format(
        entry_point=entry.tool_id,
        entry_description=entry.description,
        entry_permissions=entry.inferred_permissions,
        downstream=downstream_text,
    )
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    result = json.loads(response.content[0].text)
    return PropagationPath(
        entry_point=entry.tool_id,
        reachable_tools=[t.tool_id for t in downstream],
        blast_radius_score=result["blast_radius_score"],
        control_summary=result["control_summary"],
        kill_chain=result["kill_chain"],
    )
