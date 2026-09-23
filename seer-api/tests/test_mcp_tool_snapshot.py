"""Snapshot of the MCP tool surface AI clients see.

Pins every tool's name, description, input schema (as sent in ``tools/list``)
and per-tool rate limit, so a refactor of the tool registry cannot silently
change what hosts discover. After an intentional change, regenerate the
fixture from the seer-api directory and review the diff:

    python -m tests.test_mcp_tool_snapshot
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from seer_api.mcp import server

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_tools.json"

# The record-type list is rendered from the binding (and drift-guarded by
# test_mcp_validation), so the snapshot pins where it appears, not its text.
_RECORD_TYPE_PLACEHOLDER = "<RECORD_TYPE_DESC>"


def _normalize(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _normalize(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_normalize(v) for v in node]
    return _RECORD_TYPE_PLACEHOLDER if node == server._RECORD_TYPE_DESC else node


def _surface() -> list[dict[str, Any]]:
    tools = []
    for tool in asyncio.run(server.list_tools()):
        entry = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        entry["rate_limit"] = server._TOOL_RATE_LIMITS.get(tool.name)
        tools.append(_normalize(entry))
    return tools


def _render(tools: list[dict[str, Any]]) -> str:
    """One tool per line: compact, and a change diffs to exactly one tool."""
    lines = ",\n".join(json.dumps(t, sort_keys=True, ensure_ascii=False) for t in tools)
    return f"[\n{lines}\n]\n"


def test_mcp_tool_surface_matches_snapshot() -> None:
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert _surface() == expected


if __name__ == "__main__":
    FIXTURE.write_text(_render(_surface()), encoding="utf-8")
