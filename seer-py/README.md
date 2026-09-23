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
records = seer.dig("example.com", record_type="MX")
status  = seer.status("example.com")
results = seer.bulk_lookup(["example.com", "example.org"], concurrency=10)
```

Every call is synchronous and returns plain Python data. Errors raise
built-in exceptions: `ValueError` for invalid input, `TimeoutError` and
`ConnectionError` for transient network failures, `RuntimeError` otherwise.

Every exported function is shown in the
[Python Library section of the main README](https://github.com/TheZacillac/seer#-python-library);
`seer.__all__` lists them and `help(seer.<name>)` shows each one's docstring.
