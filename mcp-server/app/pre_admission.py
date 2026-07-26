"""Expose the real FastMCP registry over stdio for an isolated admission probe."""

from app.main import mcp


if __name__ == "__main__":
    mcp.run(transport="stdio")
