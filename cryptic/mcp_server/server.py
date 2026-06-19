from __future__ import annotations

from cryptic.mcp_server.search import get_cluster, search_iocs, summarize_collection_gap


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError("Install cryptic-cti[mcp] to run the MCP server") from e
    server = FastMCP("cryptic-cti")

    @server.tool()
    def search_iocs_tool(query: str, input_path: str | None = None, limit: int = 10) -> dict:
        return search_iocs(query, input_path=input_path, limit=limit)

    @server.tool()
    def get_cluster_tool(cluster_id: str, clusters_path: str | None = None) -> dict:
        return get_cluster(cluster_id, clusters_path=clusters_path)

    @server.tool()
    def summarize_collection_gap_tool(
        input_path: str | None = None,
        cluster_id: str | None = None,
        clusters_path: str | None = None,
    ) -> dict:
        return summarize_collection_gap(
            input_path=input_path,
            cluster_id=cluster_id,
            clusters_path=clusters_path,
        )

    return server


def main() -> None:
    try:
        server = build_server()
    except Exception as e:
        raise SystemExit(f"MCP server failed to start: {e}") from e
    server.run()


if __name__ == "__main__":
    main()
