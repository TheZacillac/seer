"""safe_error_message must strip control/ANSI bytes, not just length-cap.

`safe_error_message(ValueError(...))` previously returned the raw message
truncated to 200 chars, trusting that seer-core had pre-sanitized it. The
Python layer added no defense of its own, so a future verbose core error
could put ANSI escapes or control characters onto a REST 400 body or an SSE
`error` event. These tests pin the sanitization at the Python boundary.
Hermetic (no network, no seer binding needed).
"""

from __future__ import annotations

from seer_api.errors import _MAX_VALUE_ERROR_LEN, safe_error_message


def test_value_error_strips_control_and_ansi_bytes():
    msg = safe_error_message(ValueError("bad\x1b[31m\x00input\nhere"))
    # No C0/C1 control bytes, no ESC, no CR/LF survive.
    assert "\x1b" not in msg
    assert "\x00" not in msg
    assert "\n" not in msg
    assert "\r" not in msg
    # The printable characters are preserved (only the control/ANSI bytes
    # are removed); "[31m" is printable text and is intentionally kept.
    assert msg == "bad[31minputhere"


def test_value_error_still_length_capped_after_sanitization():
    raw = "x" * (_MAX_VALUE_ERROR_LEN + 50)
    msg = safe_error_message(ValueError(raw))
    assert len(msg) <= _MAX_VALUE_ERROR_LEN


def test_control_bytes_are_stripped_before_the_length_cap():
    # A message that is entirely control bytes followed by real text must not
    # have its visible content pushed past the cap by the stripped bytes.
    raw = ("\x1b" * 300) + "tail"
    msg = safe_error_message(ValueError(raw))
    assert "tail" in msg
    assert "\x1b" not in msg
    assert len(msg) <= _MAX_VALUE_ERROR_LEN


def test_non_value_error_messages_remain_canonical():
    # Regression: sanitization must not change the canonical strings for the
    # type-matched branches.
    assert safe_error_message(TimeoutError("anything")) == "request timed out"
    assert safe_error_message(ConnectionError("x")) == "upstream connection failed"
    assert safe_error_message(RuntimeError("x")) == "Request failed"
