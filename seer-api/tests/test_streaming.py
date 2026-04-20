"""SSE streaming bulk-endpoint integration test.

One end-to-end test over /status/bulk/stream proves the shared streaming
helper works. Other /bulk/stream endpoints use the same helper.
"""

import json
from unittest.mock import patch


def _parse_sse(body: str) -> list[dict]:
    """Parse an SSE response body into a list of {event, data} dicts."""
    events = []
    for block in body.strip().split("\n\n"):
        event = None
        data = None
        for line in block.splitlines():
            if line.startswith("event: "):
                event = line[len("event: "):]
            elif line.startswith("data: "):
                data = line[len("data: "):]
        if event is None or data is None:
            continue
        events.append({"event": event, "data": json.loads(data)})
    return events


def test_status_bulk_stream_emits_expected_event_sequence(client):
    """Submitting 2 domains should produce 2 progress, 2 item, 1 done event."""
    resp = client.post(
        "/status/bulk/stream",
        json={"domains": ["example.com", "iana.org"], "concurrency": 2},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/event-stream")

    events = _parse_sse(resp.text)
    event_types = [e["event"] for e in events]

    # Exactly 2 progress, 2 item, 1 done
    assert event_types.count("progress") == 2, event_types
    assert event_types.count("item") == 2, event_types
    assert event_types.count("done") == 1, event_types

    # done is the final event
    assert event_types[-1] == "done"

    # All progress events come before any item event (per spec ordering guarantee)
    first_item_idx = event_types.index("item")
    assert all(event_types[i] == "progress" for i in range(first_item_idx)), (
        f"progress/item interleave not allowed; got {event_types}"
    )

    # progress fields
    progresses = [e for e in events if e["event"] == "progress"]
    for p in progresses:
        assert set(p["data"].keys()) == {"completed", "total", "current_domain"}
        assert p["data"]["total"] == 2

    # item fields
    items = [e for e in events if e["event"] == "item"]
    for it in items:
        assert "success" in it["data"]
        assert "duration_ms" in it["data"]

    # done totals line up
    done = next(e for e in events if e["event"] == "done")
    assert done["data"]["total"] == 2
    assert done["data"]["succeeded"] + done["data"]["failed"] == 2


# ---------------------------------------------------------------------------
# D6 (H13): SSE error events are sanitized — no internal paths, no Rust
# panic strings, no Python tracebacks leak past the response headers.
# ---------------------------------------------------------------------------


def _parse_sse_text(body: str):
    """Lightweight SSE parser used only by the error-sanitization test."""
    events = []
    for block in body.strip().split("\n\n"):
        event = None
        data = None
        for line in block.splitlines():
            if line.startswith("event: "):
                event = line[len("event: "):]
            elif line.startswith("data: "):
                data = line[len("data: "):]
        if event is None or data is None:
            continue
        events.append({"event": event, "data": json.loads(data)})
    return events


def test_sse_error_is_sanitized(client):
    """A RuntimeError raised inside the bulk executor must not leak
    its message verbatim through the SSE error event. The event body
    must carry the generic fallback message."""
    import seer

    # Build an exception message that would leak if we used str(exc).
    leaked = (
        "thread panicked at '/home/zac/Projects/seer/seer-core/src/"
        "bulk/executor.rs:142': internal_secret=abc123"
    )

    def _raising_bulk_status(domains, concurrency, progress=None):
        raise RuntimeError(leaked)

    with patch.object(seer, "bulk_status", _raising_bulk_status):
        resp = client.post(
            "/status/bulk/stream",
            json={"domains": ["example.com"], "concurrency": 1},
        )
        assert resp.status_code == 200
        events = _parse_sse_text(resp.text)

    error_events = [e for e in events if e["event"] == "error"]
    assert len(error_events) == 1
    msg = error_events[0]["data"]["message"]
    # The raw RuntimeError message must not appear.
    assert "/home/zac" not in msg
    assert "internal_secret" not in msg
    assert "panicked" not in msg
    assert "executor.rs" not in msg
    # It should be the generic fallback for an unknown exception type.
    assert msg == "bulk operation failed"


def test_sse_error_value_error_surfaces_message(client):
    """ValueError is classified as client validation error, so its
    message is preserved (it's already sanitized by seer-core)."""
    import seer

    def _raising_bulk_status(domains, concurrency, progress=None):
        raise ValueError("refusing to connect to reserved address: 10.0.0.1")

    with patch.object(seer, "bulk_status", _raising_bulk_status):
        resp = client.post(
            "/status/bulk/stream",
            json={"domains": ["example.com"], "concurrency": 1},
        )
        assert resp.status_code == 200
        events = _parse_sse_text(resp.text)

    error_events = [e for e in events if e["event"] == "error"]
    assert len(error_events) == 1
    msg = error_events[0]["data"]["message"]
    assert "10.0.0.1" in msg
    assert "reserved" in msg.lower()
