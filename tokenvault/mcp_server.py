"""TOKENVAULT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from tokenvault.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-tokenvault[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-tokenvault[mcp]'")
        return 1
    app = FastMCP("tokenvault")

    @app.tool()
    def tokenvault_scan(target: str) -> str:
        """Self-hostable PCI tokenization microservice and CLI that swaps PANs for format-preserving tokens and proves no raw card data persists.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
