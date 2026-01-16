"""Seer API - FastAPI server and MCP integration for domain utilities."""

try:
    from importlib.metadata import version
    __version__ = version("seer-api")
except Exception:
    __version__ = "unknown"
