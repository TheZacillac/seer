"""SEER_LOG_LEVEL must reach the root logger.

`seer_api.main` imports `seer_api.mcp.server` before running its own
`logging.basicConfig(level=SEER_LOG_LEVEL)`. The MCP module used to call
`logging.basicConfig(level=INFO)` at import time, which installed a root
handler first and turned main's call into a silent no-op — SEER_LOG_LEVEL was
ignored. The MCP module now configures logging only in its stdio `run()`.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent


def test_seer_log_level_sets_root_logger_level():
    """Import the app in a fresh interpreter (pytest itself owns the root
    logger here) and check the level SEER_LOG_LEVEL asked for is in force."""
    if importlib.util.find_spec("arcanum") is not None:
        pytest.skip("arcanum's configure_logging owns the level when installed")
    # conftest installs the `seer` stub when the compiled binding is missing,
    # then imports seer_api.main — exactly the import order that matters.
    code = (
        "import sys, logging\n"
        f"sys.path.insert(0, {str(_TESTS_DIR)!r})\n"
        "import conftest  # noqa: F401\n"
        "print(logging.getLogger().level)\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "ARCANUM_LOG_LEVEL"}
    env["SEER_LOG_LEVEL"] = "WARNING"
    out = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    assert out.stdout.strip().splitlines()[-1] == str(logging.WARNING), out.stdout


def test_mcp_stdio_entry_point_still_configures_logging(monkeypatch):
    """Moving basicConfig out of import time must keep `seer-mcp` logging."""
    from seer_api.mcp import server

    calls: list[dict] = []
    monkeypatch.setattr(logging, "basicConfig", lambda **kw: calls.append(kw))
    monkeypatch.setattr(server.asyncio, "run", lambda coro: coro.close())
    server.run()
    assert len(calls) == 1
    assert calls[0]["level"] == logging.INFO
