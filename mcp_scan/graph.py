import json
import re
import networkx as nx
from .models import ToolManifest


def build_graph(tools: list[ToolManifest]) -> nx.DiGraph:
    G = nx.DiGraph()
    for tool in tools:
        G.add_node(tool.tool_id, manifest=tool)
    _add_shared_resource_edges(G, tools)
    _add_description_ref_edges(G, tools)
    _add_permission_overlap_edges(G, tools)
    return G


def get_reachable_tools(G: nx.DiGraph, tool_id: str) -> list[str]:
    if tool_id not in G:
        return []
    return list(nx.descendants(G, tool_id))


def _add_shared_resource_edges(G: nx.DiGraph, tools: list[ToolManifest]) -> None:
    resource_map: dict[str, list[str]] = {}
    for tool in tools:
        tokens = re.findall(r'/[\w/.\-]+\.[\w]+|\$\w{3,}', json.dumps(tool.input_schema))
        for token in tokens:
            resource_map.setdefault(token, []).append(tool.tool_id)
    for token, ids in resource_map.items():
        if len(ids) > 1:
            for i, src in enumerate(ids):
                for dst in ids[i + 1:]:
                    if not G.has_edge(src, dst):
                        G.add_edge(src, dst, edge_type="shared_resource", resource=token)
                    if not G.has_edge(dst, src):
                        G.add_edge(dst, src, edge_type="shared_resource", resource=token)


def _add_description_ref_edges(G: nx.DiGraph, tools: list[ToolManifest]) -> None:
    name_to_id = {t.tool_name: t.tool_id for t in tools}
    for tool in tools:
        desc_lower = tool.description.lower()
        for other_name, other_id in name_to_id.items():
            if other_name == tool.tool_name:
                continue
            if re.search(rf'\b{re.escape(other_name.lower())}\b', desc_lower):
                if not G.has_edge(tool.tool_id, other_id):
                    G.add_edge(tool.tool_id, other_id, edge_type="description_ref")


def _add_permission_overlap_edges(G: nx.DiGraph, tools: list[ToolManifest]) -> None:
    for i, a in enumerate(tools):
        for b in tools[i + 1:]:
            shared = sorted(set(a.inferred_permissions) & set(b.inferred_permissions))
            if shared:
                if not G.has_edge(a.tool_id, b.tool_id):
                    G.add_edge(a.tool_id, b.tool_id, edge_type="permission_overlap", permissions=shared)
                if not G.has_edge(b.tool_id, a.tool_id):
                    G.add_edge(b.tool_id, a.tool_id, edge_type="permission_overlap", permissions=shared)
