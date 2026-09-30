# seer-py

Python bindings for [Seer](https://github.com/TheZacillac/seer), built with
PyO3 on top of the Rust `seer-core` library: WHOIS, RDAP, DNS, propagation,
SSL, domain status, security posture and bulk operations from Python.

## Installation

The distribution is named `domain-seer` (PyPI publishing is planned); the
import name is `seer`. Build from a checkout with a Rust toolchain:

```bash
pip install ./seer-py
# or, for development
cd seer-py && maturin develop --release
```

Requires Python 3.10+. Wheels use the stable ABI (abi3).

## Usage

```python
import seer

result  = seer.lookup("example.com")                 # RDAP first, WHOIS fallback
answer  = seer.dig("example.com", record_type="MX")  # status, flags, answers, ...
trace   = seer.dns_trace("example.com")              # delegation walk from the root
status  = seer.status("example.com")
results = seer.bulk_lookup(["example.com", "example.org"], concurrency=10)
```

Every call is synchronous and returns plain Python data. Invalid input raises
`ValueError`, a timeout `TimeoutError` and a WHOIS connect failure
`ConnectionError`. Every other failure raises a subclass of `seer.SeerError`
(itself a `RuntimeError`): `RateLimitedError`, `WhoisServerNotFoundError`,
`DnsError`, `UpstreamError` (a WHOIS/RDAP/HTTP upstream failed),
`LookupFailedError`, `ParseError`, `TlsError` or `ConfigError`.

Every exported function is shown in the
[Python Library section of the main README](https://github.com/TheZacillac/seer#-python-library);
`seer.__all__` lists them and `help(seer.<name>)` shows each one's docstring.
