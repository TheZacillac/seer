"""seer-core's shared contract, loaded once from the bindings.

seer-core owns the error-category status table (`ErrorCategory`) and the
input and rate-limit contract (its `contract` module); seer-py exposes them
as ``seer.error_status_table()``, ``seer.contract()`` and
``seer.clean_message()``. Everything in seer-api that needs one of those
values imports it from here, so no number is written twice.

The lookups run at import. A compiled extension that predates these
bindings (a stale dev build) fails right here with instructions, instead of
an ``AttributeError`` on some later request.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import seer


def _binding(name: str) -> Callable[..., Any]:
    """``seer.<name>``, or an ImportError saying how to rebuild the bindings."""
    try:
        return getattr(seer, name)
    except AttributeError as exc:
        raise ImportError(
            f"the installed seer bindings have no `{name}`; they predate this "
            "seer-api. Rebuild them with `cd seer-py && maturin develop --release`."
        ) from exc


# Every key seer-api reads from `seer.contract()`.
_CONTRACT_KEYS = (
    "domain_max_length",
    "nameserver_max_length",
    "record_type_max_length",
    "record_type_pattern",
    "message_max_length",
    "tld_token_pattern",
    "concurrency_max",
    "rate_limits",
)


def _load_contract() -> dict[str, Any]:
    """``seer.contract()``, checked for every key seer-api reads."""
    contract = _binding("contract")()
    missing = [key for key in _CONTRACT_KEYS if key not in contract]
    if missing:
        raise ImportError(
            f"the installed seer bindings' contract has no {', '.join(missing)}; "
            "they predate this seer-api. Rebuild them with "
            "`cd seer-py && maturin develop --release`."
        )
    return contract


# Limits and rate-limit classes: see seer-core's `contract` module.
CONTRACT: dict[str, Any] = _load_contract()

# (exception class, HTTP status) rows in match order; `seer.SeerError`, the
# base class, is last.
ERROR_STATUS_TABLE: tuple[tuple[type[BaseException], int], ...] = tuple(
    _binding("error_status_table")()
)

# Strips control/ANSI bytes from error text, then caps its length.
clean_message: Callable[[str], str] = _binding("clean_message")
