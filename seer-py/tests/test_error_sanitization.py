"""Error-sanitization tests for the PyO3 surface.

Verifies that `SeerError` variants are mapped to typed Python exceptions via
`SeerError::sanitized_message()` — raw internal text (URLs, paths, system
errors) must not leak to the caller, and validation-shaped errors must land
as `ValueError` so callers can catch them by type rather than substring.

These tests are hermetic: `validate_public_host` on a loopback IP literal
needs no network, and `whois` on a clearly invalid domain is rejected by the
normalization layer before any socket is opened.
"""

import pytest
import seer


def test_invalid_input_is_value_error():
    """A reserved-range IP literal must raise ValueError, not RuntimeError."""
    with pytest.raises(ValueError) as exc:
        seer.validate_public_host("127.0.0.1", 80)
    msg = str(exc.value).lower()
    assert "reserved" in msg or "invalid" in msg, (
        f"expected sanitized message mentioning reserved/invalid, got: {exc.value!r}"
    )


def test_metadata_ip_is_value_error():
    """The cloud-metadata IP (169.254.169.254) must be rejected as ValueError."""
    with pytest.raises(ValueError):
        seer.validate_public_host("169.254.169.254", 80)


def test_invalid_domain_is_value_error():
    """An obviously invalid domain must raise ValueError via InvalidDomain."""
    with pytest.raises(ValueError):
        seer.whois("not a valid domain with spaces")


def test_dig_bare_srv_is_value_error():
    """A bare-domain SRV query (no `_service._proto` labels) is a usage error,
    not a transient DNS failure. It must raise ValueError (via InvalidInput) so
    the MCP/HTTP layers classify it as permanent and never advise a retry.
    Resolves at parse time in seer-core, so this is hermetic — no network."""
    with pytest.raises(ValueError) as exc:
        seer.dig("example.com", "SRV")
    assert "_service._proto" in str(exc.value)


def test_sanitized_message_has_no_internal_leakage():
    """Error text from validate_public_host must not contain file paths or
    reqwest-style URLs. The sanitized_message() path keeps it to a terse
    human string."""
    with pytest.raises(ValueError) as exc:
        seer.validate_public_host("10.0.0.1", 443)
    msg = str(exc.value)
    # These are markers of unsanitized leakage — they must not appear.
    assert "/home/" not in msg
    assert "src/" not in msg
    assert "reqwest::" not in msg
