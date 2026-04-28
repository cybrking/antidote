from antidote_mcp.models import ToolManifest
from antidote_mcp.graph import build_graph, get_reachable_tools


def _tool(server: str, name: str, description: str = "", schema: dict | None = None, perms: list | None = None) -> ToolManifest:
    return ToolManifest(
        server_name=server, tool_name=name,
        description=description,
        input_schema=schema or {},
        inferred_permissions=perms or [],
    )


def test_nodes_created_per_tool():
    G = build_graph([_tool("s", "a"), _tool("s", "b")])
    assert "s/a" in G.nodes and "s/b" in G.nodes


def test_shared_resource_edge():
    tools = [
        _tool("s", "writer", schema={"properties": {"path": {"default": "/tmp/data.json"}}}),
        _tool("s", "reader", schema={"properties": {"path": {"default": "/tmp/data.json"}}}),
    ]
    G = build_graph(tools)
    assert G.has_edge("s/writer", "s/reader") or G.has_edge("s/reader", "s/writer")


def test_description_ref_edge():
    tools = [
        _tool("s", "process", description="Calls read_data to get input"),
        _tool("s", "read_data", description="Reads raw data from disk"),
    ]
    G = build_graph(tools)
    assert G.has_edge("s/process", "s/read_data")


def test_permission_overlap_edge():
    tools = [
        _tool("s", "a", perms=["filesystem.write", "network.outbound"]),
        _tool("s", "b", perms=["filesystem.write", "secrets.read"]),
    ]
    G = build_graph(tools)
    edge = G.get_edge_data("s/a", "s/b") or G.get_edge_data("s/b", "s/a")
    assert edge is not None
    assert "filesystem.write" in edge["permissions"]


def test_get_reachable_tools_chain():
    tools = [
        _tool("s", "fetch", schema={"properties": {"path": {"default": "/tmp/a.json"}}}),
        _tool("s", "read", schema={"properties": {"path": {"default": "/tmp/a.json"}}}),
        _tool("s", "report", description="Calls read to generate output"),
    ]
    G = build_graph(tools)
    assert "s/read" in get_reachable_tools(G, "s/fetch")


def test_no_edges_for_unrelated_tools():
    G = build_graph([_tool("s", "a"), _tool("s", "b")])
    assert G.number_of_edges() == 0
