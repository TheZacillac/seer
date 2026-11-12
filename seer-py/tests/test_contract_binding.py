"""seer-core's shared contract, as the bindings expose it.

``error_status_table``, ``contract`` and ``clean_message`` are pure data:
they let seer-api read core's status codes and limits instead of keeping
its own copy.
"""

import seer


def test_error_status_table_maps_each_class_to_cores_status():
    table = dict(seer.error_status_table())
    assert table == {
        ValueError: 400,
        TimeoutError: 504,
        ConnectionError: 502,
        seer.RateLimitedError: 429,
        seer.WhoisServerNotFoundError: 404,
        seer.DnsError: 502,
        seer.UpstreamError: 502,
        seer.LookupFailedError: 502,
        seer.ParseError: 502,
        seer.TlsError: 502,
        seer.ConfigError: 500,
        seer.SeerError: 500,
    }


def test_error_status_table_lists_the_base_class_last():
    # A first-match isinstance walk must reach every subclass row before the
    # seer.SeerError row that would also match it.
    classes = [cls for cls, _status in seer.error_status_table()]
    assert classes[-1] is seer.SeerError
    assert len(classes) == len(set(classes))


def test_contract_carries_cores_limits():
    assert seer.contract() == {
        "domain_max_length": 253,
        "nameserver_max_length": 512,
        "record_type_max_length": 10,
        "record_type_pattern": "^[A-Z0-9]+$",
        "message_max_length": 200,
        "rate_limits": {"light": 60, "standard": 30, "moderate": 20, "heavy": 5},
    }


def test_clean_message_strips_controls_then_caps():
    assert seer.clean_message("a\r\n\x1b[31mb\x00") == "a[31mb"
    padded = "\x00" * 500 + "x" * 300
    assert seer.clean_message(padded) == "x" * 200
