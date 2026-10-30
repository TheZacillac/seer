"""A stale or incompatible compiled extension must fail with a clear fix.

When ``seer._seer`` lags the Python layer, ``from seer._seer import ...`` fails
with a bare "cannot import name '...'" that has crash-looped the MCP server more
than once (bulk_ssl, subdomains_classify, ConfigError). ``_stale_extension_error``
rephrases that into a rebuild instruction; this locks the behaviour in. Hermetic:
it drives the helper directly, so no broken ``.so`` is needed.
"""

import seer


def test_stale_extension_error_names_cause_and_fix():
    original = ImportError("cannot import name 'bulk_ssl' from 'seer._seer'")
    err = seer._stale_extension_error(original)

    assert isinstance(err, ImportError)
    msg = str(err)
    assert "seer._seer" in msg  # points at the real subsystem
    assert "cannot import name 'bulk_ssl'" in msg  # echoes the underlying cause
    assert "maturin develop" in msg  # tells the reader how to fix it
