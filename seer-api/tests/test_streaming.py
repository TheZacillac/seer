"""SSE streaming bulk-endpoint integration test.

One end-to-end test over /status/bulk/stream proves the shared streaming
helper works. Other /bulk/stream endpoints use the same helper.
"""

import json


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
