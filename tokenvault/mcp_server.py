"""TOKENVAULT MCP server — exposes detect_pans() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
from tokenvault.core import detect_pans


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-tokenvault[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-tokenvault[mcp]'")
        return 1
    app = FastMCP("tokenvault")

    @app.tool()
    def tokenvault_scan(text: str) -> str:
        """Scan text for PAN card numbers.

        Returns a JSON object with 'count' and 'findings' (masked PANs with
        position and Luhn-validity). No raw card data is returned.
        """
        hits = detect_pans(text, require_luhn=True)
        return json.dumps(
            {"count": len(hits), "findings": [h.to_dict() for h in hits]},
            indent=2,
        )

    app.run()
    return 0
