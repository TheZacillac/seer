"""Validated environment-variable parsing.

The lifespan startup checks and the dispatch/streaming bounds read integer
tunables from the environment. A bare ``int(os.environ[...])`` raises an opaque
``ValueError`` traceback on a non-numeric value (e.g. ``WEB_CONCURRENCY=auto``,
a common PaaS convention), instead of the deliberate, readable ``RuntimeError``
the surrounding fail-closed checks use. ``env_int`` centralizes that parsing
with a clear error message (issue #50).
"""

from __future__ import annotations

import os


def env_int(name: str, default: int, *, min_value: int | None = None) -> int:
    """Read integer env var ``name``, falling back to ``default`` when unset.

    Raises ``RuntimeError`` with a clear message when the variable is set to a
    non-integer value. When ``min_value`` is given, values below it are clamped
    up to ``min_value`` (mirroring the previous ``max(1, int(...))`` idiom).
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError:
            raise RuntimeError(
                f"{name} must be an integer (got {raw!r})"
            ) from None
    if min_value is not None and value < min_value:
        value = min_value
    return value
