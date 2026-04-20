# Adversarial Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate all 35 findings from the adversarial code review (8 critical, 14 high, 13 medium) in a single PR.

**Architecture:** Share one SSRF-validation helper across `seer-core`, `seer-py`, and `seer-api`. Swap blocking primitives for Tokio equivalents in async-touching code. Bind the API to loopback by default (breaking change, explicitly approved). Add recursion/size limits at every untrusted-input boundary. Add hermetic tests for critical paths currently uncovered.

**Tech Stack:** Rust (seer-core, seer-cli, seer-py via PyO3), Python 3.9+ (seer-api FastAPI + MCP), cargo/pytest/maturin.

**Branch:** `claude/adversarial-review-fixes-<timestamp>` (already created)

**Working assumptions:**
1. All fixes land in one PR to main.
2. `seer-api` default bind changes from `0.0.0.0` to `127.0.0.1` — explicitly approved breaking change.
3. Each batch is a single commit with a conventional-commit message (`fix(core): …`, `fix(api): …`, etc.). Final commit squashes if requested.
4. Tests must pass hermetically — no live network in default `cargo test` / `pytest`. Live tests gated behind `#[ignore]` or a `SEER_LIVE_TESTS=1` env flag.

---

## Task 0: Pre-flight

**Files:** none (verification only)

- [ ] **Step 0.1:** Confirm clean tree on new branch.

Run: `git status && git branch --show-current`
Expected: clean, branch `claude/adversarial-review-fixes-*`.

- [ ] **Step 0.2:** Baseline: confirm existing tests pass before we change anything.

Run:
```
cd /home/zac/Projects/arcanum_suite/seer
cargo test --workspace --no-fail-fast 2>&1 | tail -40
cd seer-api && python -m pytest -x 2>&1 | tail -20
```
Expected: pass (or document current baseline failures in commit message so we can distinguish regressions).

- [ ] **Step 0.3:** Remove committed `.venv` if it's tracked.

Run:
```
git ls-files seer-py/.venv | head -5
# If any output:
git rm -rf --cached seer-py/.venv 2>/dev/null || true
rm -rf seer-py/.venv
grep -q "^seer-py/.venv/$" .gitignore || echo "seer-py/.venv/" >> .gitignore
```

---

## Batch A: Shared SSRF Validator (fixes C7, H1, M7, and C3/A4 prerequisite)

**Theme:** One helper, used everywhere. Every outbound leg (WHOIS referral, CT log, status probe, DNS `nameserver` param, MCP tools) calls it.

### Task A1: Create `seer-core::net::validate_public_addr`

**Files:**
- Create: `seer-core/src/net.rs`
- Modify: `seer-core/src/lib.rs` (add `pub mod net;`)
- Modify: `seer-core/Cargo.toml` (may need to add `once_cell` if not present — check first)
- Test: inline `#[cfg(test)] mod tests` in `net.rs`

- [ ] **Step A1.1: Write the failing tests first**

Add to `seer-core/src/net.rs` (create new file):

```rust
//! Shared SSRF protection helpers.
//!
//! `validate_public_addr` rejects any hostname/IP that resolves to a reserved,
//! loopback, link-local, private, multicast, benchmarking, documentation, or
//! cloud-metadata address range. Used by every outbound leg of seer to ensure
//! user-supplied domains cannot be weaponized as an SSRF primitive.

use std::net::IpAddr;
use tokio::net::lookup_host;

use crate::error::{Result, SeerError};

/// Reject an IP address if it belongs to any range that is not appropriate
/// for outbound queries from a public-facing tool.
///
/// This covers: loopback, private (RFC1918), link-local (incl. 169.254.169.254
/// cloud metadata), multicast, unspecified, documentation, benchmarking,
/// IPv6 ULA, and IPv6 link-local.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64.0.0/10 — carrier-grade NAT / shared address space.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                // 192.0.0.0/24 — IETF reserved.
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 — network benchmark.
                || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // Unique-local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:0:0/96) — check embedded IPv4
                || v6.to_ipv4_mapped().map_or(false, |v4| {
                    is_reserved_ip(IpAddr::V4(v4))
                })
        }
    }
}

/// Resolve a hostname and verify every resolved address is public.
/// Port is required because DNS resolution is done through `lookup_host`.
///
/// Returns `Ok(())` when all resolved IPs are public; `Err(SeerError::InvalidInput)`
/// otherwise. Does NOT follow CNAMEs explicitly — relies on the OS resolver.
pub async fn validate_public_host(host: &str, port: u16) -> Result<()> {
    // Short-circuit: IP literal parse
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_reserved_ip(ip) {
            return Err(SeerError::InvalidInput(format!(
                "refusing to connect to reserved address: {}",
                ip
            )));
        }
        return Ok(());
    }

    let addrs: Vec<_> = lookup_host((host, port))
        .await
        .map_err(|e| SeerError::InvalidInput(format!("DNS resolution failed for {host}: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(SeerError::InvalidInput(format!(
            "no addresses resolved for {host}"
        )));
    }

    for sa in &addrs {
        if is_reserved_ip(sa.ip()) {
            return Err(SeerError::InvalidInput(format!(
                "{host} resolves to reserved address {}",
                sa.ip()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_v4() {
        assert!(is_reserved_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_metadata_v4() {
        assert!(is_reserved_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(is_reserved_ip("10.0.0.1".parse().unwrap()));
        assert!(is_reserved_ip("172.16.0.1".parse().unwrap()));
        assert!(is_reserved_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_cgnat() {
        assert!(is_reserved_ip("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_benchmarking() {
        assert!(is_reserved_ip("198.18.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(is_reserved_ip("::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_ula() {
        assert!(is_reserved_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv4_mapped_loopback() {
        assert!(is_reserved_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_v4() {
        assert!(!is_reserved_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_reserved_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_v6() {
        assert!(!is_reserved_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn validate_rejects_ip_literal_loopback() {
        let err = validate_public_host("127.0.0.1", 80).await.unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn validate_rejects_ip_literal_metadata() {
        let err = validate_public_host("169.254.169.254", 80).await.unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn validate_allows_public_ip_literal() {
        validate_public_host("8.8.8.8", 53).await.unwrap();
    }
}
```

Add to `seer-core/src/lib.rs` after the last `pub mod` line:

```rust
pub mod net;
```

- [ ] **Step A1.2: Run and verify failure, then pass**

```
cargo test -p seer-core net::tests 2>&1 | tail -30
```
Expected: all pass. If `SeerError::InvalidInput` doesn't exist, check `seer-core/src/error.rs` and either use the closest existing variant (probably `ValidationError` or `InvalidDomain`) or add `InvalidInput(String)` there.

- [ ] **Step A1.3: Commit**

```
git add seer-core/src/net.rs seer-core/src/lib.rs
git commit -m "feat(core): add shared SSRF validation helper

Introduces seer_core::net::{is_reserved_ip, validate_public_host} used by
WHOIS referral, CT log, status, DNS, and API/MCP paths to reject outbound
connections to reserved IP ranges (loopback, RFC1918, link-local, CGNAT,
cloud metadata, IPv6 ULA). Covers IPv4-mapped IPv6 addresses explicitly."
```

### Task A2: Wire validator into WHOIS TCP connect (H1, Medium amplifier)

**Files:**
- Modify: `seer-core/src/whois/client.rs` in `query_server_internal` (around line 282-303 per review) and `discover_whois_server_with_retry` (around 247-278).

- [ ] **Step A2.1: Read the file first**

```
Read seer-core/src/whois/client.rs
```

- [ ] **Step A2.2: In `query_server_internal`, before `TcpStream::connect`, call validator**

Pattern:
```rust
// Before the TcpStream::connect call:
crate::net::validate_public_host(server, 43).await?;
let stream = tokio::time::timeout(
    connect_timeout,
    TcpStream::connect(&format!("{server}:43")),
).await??;
```

- [ ] **Step A2.3: In `discover_whois_server_with_retry`, validate before caching the discovered hostname.**

After IANA returns a whois server hostname and before inserting into `DISCOVERED_SERVERS`:
```rust
crate::net::validate_public_host(&discovered_server, 43).await?;
DISCOVERED_SERVERS.insert(tld, discovered_server.clone());
```

- [ ] **Step A2.4: Add tests**

Add to the `tests` module in `seer-core/src/whois/client.rs`:
```rust
#[tokio::test]
async fn whois_refuses_loopback_referral() {
    // Directly call query_server_internal (make visible to tests if needed)
    // with "127.0.0.1" as server -> expect InvalidInput.
}
```

If `query_server_internal` is private, expose a `pub(crate)` test helper. Prefer a small refactor over test-only public APIs.

- [ ] **Step A2.5: Run and commit**

```
cargo test -p seer-core whois 2>&1 | tail -30
git add seer-core/src/whois/client.rs
git commit -m "fix(core): validate WHOIS referral hostnames against SSRF"
```

### Task A3: Wire validator into CT log client (C3 part 1, theme)

**Files:**
- Modify: `seer-core/src/subdomains.rs` (lines 28-34 for client builder, 64-68 for request, 88-98 for response).

- [ ] **Step A3.1: Change the static HTTP client to disable redirects and use a resolver guard**

At the `Lazy<HttpClient>` init, add:
```rust
.redirect(reqwest::redirect::Policy::none())
```

and switch from `expect(...)` to returning a `Result` on first use (addresses M1 for this client specifically).

- [ ] **Step A3.2: Before the HTTP request, validate the crt.sh host**

```rust
// crt.sh is the hardcoded host. Validate even though it's hardcoded,
// because if the upstream ever changes to user-influenced we're safe.
crate::net::validate_public_host("crt.sh", 443).await?;
```

Actually, since `crt.sh` is hardcoded: the required change is the **redirect policy** (redirects could go anywhere) plus **streaming cap** (see Task B4) — not a validation on the known host. Skip the pre-validation here; the redirect policy is the primary mitigation.

- [ ] **Step A3.3: Commit**

```
git add seer-core/src/subdomains.rs
git commit -m "fix(core): disable redirects on CT log client to prevent SSRF"
```

### Task A4: Expose validator from seer-py

**Files:**
- Modify: `seer-py/src/lib.rs` — add a new `#[pyfunction]` wrapping `validate_public_host`.

- [ ] **Step A4.1: Add the binding**

```rust
#[pyfunction]
fn validate_public_host_py(py: Python<'_>, host: &str, port: u16) -> PyResult<()> {
    py.allow_threads(|| {
        runtime().block_on(async {
            std::panic::AssertUnwindSafe(
                seer_core::net::validate_public_host(host, port)
            )
            .catch_unwind()
            .await
            .map_err(|_| PyRuntimeError::new_err("panic in validate_public_host"))?
            .map_err(|e| PyValueError::new_err(e.sanitized_message()))
        })
    })
}
```

*Note*: `catch_unwind` is addressed in batch C; for now the simpler form `.map_err(|e| PyValueError::new_err(e.to_string()))` is acceptable and will be uplifted in Task C2.

Register in the `#[pymodule]`:
```rust
m.add_function(wrap_pyfunction!(validate_public_host_py, m)?)?;
```

Expose in `python/seer/__init__.py`:
```python
from seer._seer_py import validate_public_host_py as validate_public_host  # noqa: F401
```

- [ ] **Step A4.2: Commit**

```
git add seer-py/src/lib.rs seer-py/python/seer/__init__.py
git commit -m "feat(py): expose validate_public_host from seer-core"
```

### Task A5: Wire validator into API + MCP (C7, M7)

**Files:**
- Create: `seer-api/seer_api/ssrf.py` (shared helper that wraps `seer.validate_public_host`).
- Modify: `seer-api/seer_api/routers/status.py`, `dns.py`, `whois.py`.
- Modify: `seer-api/seer_api/mcp/server.py` (wrap SSRF-capable tools).

- [ ] **Step A5.1: Create the shared helper**

```python
# seer-api/seer_api/ssrf.py
"""SSRF guard for user-supplied domain/IP parameters before calling seer."""
from __future__ import annotations

from fastapi import HTTPException
import seer

def guard(host: str, port: int = 443) -> None:
    """Raise HTTPException(400) if host is not safe to query.

    Covers: IP literals in reserved ranges, hostnames resolving to reserved IPs,
    cloud-metadata addresses, loopback, and private address space.
    """
    try:
        seer.validate_public_host(host, port)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

- [ ] **Step A5.2: Call `guard(domain)` at the top of every router that does outbound**

In `status.py`, `whois.py`, `dns.py` (including the `nameserver` parameter in `dns.py` — call `guard(nameserver, 53)` when provided).

- [ ] **Step A5.3: Call `guard` from MCP tool handlers**

In `mcp/server.py`, for each tool that accepts a domain/IP/nameserver: dispatch through the same guard before invoking seer.

- [ ] **Step A5.4: Add tests**

In `seer-api/tests/test_hardening.py`, add:
```python
@pytest.mark.parametrize("path", [
    "/status/169.254.169.254",
    "/status/127.0.0.1",
    "/status/10.0.0.1",
    "/whois/192.168.1.1",
    "/dns/example.com/A?nameserver=169.254.169.254",
])
def test_ssrf_guard_rejects_reserved(client, path):
    resp = client.get(path)
    assert resp.status_code == 400
    assert "reserved" in resp.json().get("detail", "").lower() or "invalid" in resp.json().get("detail", "").lower()
```

Note: the test client should be configured to use the real `seer.validate_public_host` (not the stub) for these tests. Either add a fixture that un-stubs just this function, or use a module-level import that bypasses the stub. Document the choice in the test.

- [ ] **Step A5.5: Commit**

```
git add seer-api/seer_api/ssrf.py seer-api/seer_api/routers/ seer-api/seer_api/mcp/server.py seer-api/tests/test_hardening.py
git commit -m "fix(api): block SSRF to reserved addresses in routers and MCP"
```

---

## Batch B: Rust Core Correctness

### Task B1: Fix async-Drop mutex + poisoning (C1, C2)

**Files:**
- Modify: `seer-core/src/lookup.rs:158-168` (Drop impl) and `:428` (acquisition in lookup_with_progress).

- [ ] **Step B1.1: Read the relevant section**

- [ ] **Step B1.2: Replace `Drop::drop` body**

Current (approx):
```rust
impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut map = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        // ... cleanup ...
    }
}
```

Target — avoid blocking in Drop; use `try_lock` with a graceful skip:
```rust
impl Drop for InflightGuard {
    fn drop(&mut self) {
        match LOOKUP_INFLIGHT.try_lock() {
            Ok(mut map) => {
                // existing cleanup
            }
            Err(std::sync::TryLockError::Poisoned(p)) => {
                let mut map = p.into_inner();
                // existing cleanup
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                // Intentional: do not block the executor from Drop.
                // The notify_waiters call below ensures waiters retry
                // against the cache on next poll, so a missed cleanup
                // is eventually self-healing (TTL + waiter retry).
                tracing::debug!("InflightGuard drop: skipping cleanup under contention");
            }
        }
        self.notify.notify_waiters();
    }
}
```

- [ ] **Step B1.3: Fix the `.expect(...)` at line 428**

Replace `LOOKUP_INFLIGHT.lock().expect("LOOKUP_INFLIGHT mutex poisoned")` with `LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner())`.

- [ ] **Step B1.4: Add a test**

```rust
#[tokio::test]
async fn inflight_guard_recovers_from_poison() {
    // Create an InflightGuard, poison the mutex via a panic, then verify
    // that subsequent lookup_with_progress calls still work.
}
```

- [ ] **Step B1.5: Run + commit**

```
cargo test -p seer-core lookup 2>&1 | tail -20
git add seer-core/src/lookup.rs
git commit -m "fix(core): survive mutex poisoning in lookup inflight tracker"
```

### Task B2: RDAP bootstrap body streaming timeout (H4)

**Files:**
- Modify: `seer-core/src/rdap/client.rs` around lines 678-693 (`read_bootstrap`).

- [ ] **Step B2.1: Wrap streaming loop**

Existing pattern:
```rust
let mut body = Vec::new();
while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    if body.len() + chunk.len() > MAX_BOOTSTRAP_SIZE {
        return Err(...);
    }
    body.extend_from_slice(&chunk);
}
```

Target:
```rust
let body = tokio::time::timeout(DEFAULT_TIMEOUT, async {
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BOOTSTRAP_SIZE {
            return Err(SeerError::ProtocolError(
                "RDAP bootstrap body exceeds size limit".into()
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Result::<Vec<u8>, SeerError>::Ok(body)
})
.await
.map_err(|_| SeerError::Timeout("RDAP bootstrap body read timed out".into()))??;
```

Match the exact pattern used at `query_rdap_internal` (lines 612-628).

- [ ] **Step B2.2: Commit**

```
cargo test -p seer-core rdap 2>&1 | tail -20
git add seer-core/src/rdap/client.rs
git commit -m "fix(core): timeout RDAP bootstrap body streaming"
```

### Task B3: RdapEntity recursion depth limit (H3)

**Files:**
- Modify: `seer-core/src/rdap/types.rs` — add a `validate_depth` method on `RdapResponse` or a post-deserialization walker.

- [ ] **Step B3.1: Add depth walker**

```rust
impl RdapResponse {
    const MAX_ENTITY_DEPTH: usize = 16;

    fn walk_depth(entities: &[RdapEntity], depth: usize) -> Result<()> {
        if depth > Self::MAX_ENTITY_DEPTH {
            return Err(SeerError::ProtocolError(
                format!("RDAP entities exceed max nesting depth {}", Self::MAX_ENTITY_DEPTH)
            ));
        }
        for e in entities {
            Self::walk_depth(&e.entities, depth + 1)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_size()?; // existing
        Self::walk_depth(&self.entities, 0)?;
        Ok(())
    }
}
```

- [ ] **Step B3.2: Call `validate()` (not just `validate_size()`) at every deserialization site**

Search for `validate_size()` callers and replace with `validate()`.

- [ ] **Step B3.3: Test**

```rust
#[test]
fn rejects_deeply_nested_entities() {
    // Build a RdapResponse with 20 levels of nested entities.
    // Assert validate() returns Err.
}
```

- [ ] **Step B3.4: Commit**

```
cargo test -p seer-core rdap 2>&1 | tail -20
git add seer-core/src/rdap/types.rs seer-core/src/rdap/client.rs
git commit -m "fix(core): bound RDAP entity nesting depth to 16"
```

### Task B4: CT log streaming size cap (C3)

**Files:**
- Modify: `seer-core/src/subdomains.rs:88-98`.

- [ ] **Step B4.1: Replace `response.bytes().await` with streaming loop**

Mirror the pattern from `rdap/client.rs::query_rdap_internal`:
```rust
use futures::StreamExt;

let mut stream = response.bytes_stream();
let mut body = Vec::new();
while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    if body.len() + chunk.len() > MAX_CT_RESPONSE_SIZE {
        return Err(SeerError::ProtocolError(
            "CT log response exceeds size limit".into()
        ));
    }
    body.extend_from_slice(&chunk);
}
```

Wrap in `tokio::time::timeout(DEFAULT_TIMEOUT, ...)`.

- [ ] **Step B4.2: Commit**

```
cargo test -p seer-core subdomains 2>&1 | tail -20
git add seer-core/src/subdomains.rs
git commit -m "fix(core): stream CT log response with size cap to prevent OOM"
```

### Task B5: Remove `.expect()` from library statics (M1)

**Files:**
- Modify: `seer-core/src/subdomains.rs:33`, `seer-core/src/rdap/client.rs:52`.

- [ ] **Step B5.1: Convert `Lazy<Client>` to `Lazy<Result<Client>>` or `OnceCell<Client>`**

Preferred: `Lazy<Option<Client>>` with `.ok()`-style conversion and callers returning `SeerError::Internal` on `None`. Avoid `expect()`.

```rust
static RDAP_HTTP_CLIENT: Lazy<Option<HttpClient>> = Lazy::new(|| {
    reqwest::Client::builder()
        // …existing config…
        .build()
        .ok()
});

fn client() -> Result<&'static HttpClient> {
    RDAP_HTTP_CLIENT
        .as_ref()
        .ok_or_else(|| SeerError::Internal("failed to build RDAP HTTP client".into()))
}
```

Update call sites to use `client()?` instead of `&*RDAP_HTTP_CLIENT`.

- [ ] **Step B5.2: Commit**

```
cargo test -p seer-core 2>&1 | tail -10
git add seer-core/src/subdomains.rs seer-core/src/rdap/client.rs
git commit -m "refactor(core): remove expect() from library HTTP client statics"
```

### Task B6: Retry classifier sees through RetryExhausted (H5)

**Files:**
- Modify: `seer-core/src/retry.rs` around `NetworkRetryClassifier::is_retryable` (line ~204) and `RetryExecutor::execute` (lines ~297-304).

- [ ] **Step B6.1: Make the wrapper transparent to the classifier**

Option A (preferred): store the original error by type, not string.
```rust
pub enum SeerError {
    // …existing…
    RetryExhausted { last_error: Box<SeerError>, attempts: usize },
}
```
If already `String`-based, keep string but make the classifier inspect the wrapped last_error recursively:
```rust
impl NetworkRetryClassifier {
    pub fn is_retryable(&self, err: &SeerError) -> bool {
        match err {
            SeerError::Timeout(_) => true,
            SeerError::ReqwestError(_) => true, // transient
            SeerError::RetryExhausted { last_error, .. } => self.is_retryable(last_error),
            _ => false,
        }
    }
}
```

- [ ] **Step B6.2: Make first-attempt errors consistent with subsequent attempts**

Always wrap in `RetryExhausted` at the public boundary, never before. Or: never wrap inside the executor, only at the public API.

Document the chosen convention in a doc comment on `RetryExecutor`.

- [ ] **Step B6.3: Test**

```rust
#[test]
fn retry_exhausted_is_retryable_if_inner_is() {
    let classifier = NetworkRetryClassifier;
    let inner = SeerError::Timeout("x".into());
    let wrapped = SeerError::RetryExhausted {
        last_error: Box::new(inner),
        attempts: 3,
    };
    assert!(classifier.is_retryable(&wrapped));
}
```

- [ ] **Step B6.4: Commit**

```
cargo test -p seer-core retry 2>&1 | tail -20
git add seer-core/src/retry.rs seer-core/src/error.rs
git commit -m "fix(core): classifier sees through RetryExhausted wrapper"
```

### Task B7: Split MITM-tolerant cert inspection from trusted HTTP fetch (H2)

**Files:**
- Modify: `seer-core/src/status/client.rs:257-258` (fetch_http_info) + `ssl.rs:121` (ssl checker).

- [ ] **Step B7.1: In `fetch_http_info`, use a default validating client**

Remove `danger_accept_invalid_certs(true)` from the status/HTTP path. Keep it **only** in `ssl.rs` where cert inspection is the point.

On cert validation failure in `fetch_http_info`, return a typed error (`HttpStatus::TlsError { reason }`) rather than proceeding.

- [ ] **Step B7.2: Commit**

```
cargo test -p seer-core status 2>&1 | tail -20
git add seer-core/src/status/client.rs
git commit -m "fix(core): require valid TLS for status HTTP fetch (MITM mitigation)"
```

### Task B8: Log + preserve corrupt user files (M2)

**Files:**
- Modify: `seer-core/src/history.rs:47`, `seer-core/src/watchlist.rs:57`.

- [ ] **Step B8.1: Replace `unwrap_or_default()` with error-aware load**

```rust
match serde_json::from_str(&content) {
    Ok(h) => h,
    Err(e) => {
        let backup = path.with_extension("corrupt");
        let _ = std::fs::rename(&path, &backup);
        tracing::warn!(
            path = %path.display(),
            backup = %backup.display(),
            error = %e,
            "history file corrupt; moved to backup and starting fresh"
        );
        LookupHistory::default()
    }
}
```

Same pattern for `watchlist.rs` with `toml::from_str`.

- [ ] **Step B8.2: Commit**

```
cargo test -p seer-core history 2>&1 | tail -10
cargo test -p seer-core watchlist 2>&1 | tail -10
git add seer-core/src/history.rs seer-core/src/watchlist.rs
git commit -m "fix(core): preserve corrupt history/watchlist as .corrupt backup"
```

---

## Batch C: PyO3 FFI

### Task C1: Put abi3-py39 in default features (H6)

**Files:**
- Modify: `seer-py/Cargo.toml:28`.

- [ ] **Step C1.1:** Change `default = []` to `default = ["abi3-py39"]`.

- [ ] **Step C1.2:** Verify maturin still works:

```
cd seer-py && maturin develop --release 2>&1 | tail -10
```

- [ ] **Step C1.3: Commit**

```
git add seer-py/Cargo.toml
git commit -m "fix(py): enable abi3-py39 by default to prevent non-ABI3 builds"
```

### Task C2: `catch_unwind` every `block_on` (C4)

**Files:**
- Modify: `seer-py/src/lib.rs` — wrap every `RUNTIME.block_on(...)` call.

- [ ] **Step C2.1: Add a helper**

```rust
use std::panic::{AssertUnwindSafe, catch_unwind};
use futures::FutureExt;

fn run_async<F, T>(py: Python<'_>, fut: F) -> PyResult<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    py.allow_threads(|| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime().block_on(fut)
        }));
        match result {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(seer_err_to_py(&e)),
            Err(_) => Err(PyRuntimeError::new_err(
                "panic in seer runtime (likely nested async context)"
            )),
        }
    })
}

fn seer_err_to_py(e: &SeerError) -> PyErr {
    match e {
        SeerError::InvalidInput(_) => PyValueError::new_err(e.sanitized_message()),
        SeerError::InvalidDomain(_) => PyValueError::new_err(e.sanitized_message()),
        SeerError::Timeout(_) => PyRuntimeError::new_err(format!("timeout: {}", e.sanitized_message())),
        _ => PyRuntimeError::new_err(e.sanitized_message()),
    }
}
```

- [ ] **Step C2.2: Migrate every `#[pyfunction]`**

Replace each body's direct `runtime().block_on(...)` with `run_async(py, ...)`.

- [ ] **Step C2.3: Test**

Add test that forces `block_on` from inside a tokio context via a subprocess:
```python
# tests/test_ffi_safety.py
import subprocess, sys, textwrap

def test_block_on_in_async_returns_error_not_abort():
    code = textwrap.dedent("""
        import asyncio, seer
        async def main():
            # We can't directly cause the panic cleanly, but we can verify
            # that seer.lookup completes without aborting when called from
            # inside an already-running asyncio loop.
            return seer.lookup("example.com")
        try:
            asyncio.run(main())
        except RuntimeError as e:
            # Accept: RuntimeError with informative message.
            assert "seer" in str(e).lower() or "runtime" in str(e).lower()
    """)
    # Run as subprocess so an abort would show as nonzero exit
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr.decode()
```

Mark this test as `@pytest.mark.skipif(not LIVE_NETWORK, ...)` if it requires network.

- [ ] **Step C2.4: Commit**

```
cd seer-py && maturin develop --release 2>&1 | tail -5
cd .. && cd seer-py && pytest 2>&1 | tail -10
git add seer-py/src/lib.rs seer-py/tests/test_ffi_safety.py
git commit -m "fix(py): catch_unwind around block_on to prevent process abort"
```

### Task C3: follow_cancel_sender poisoning + concurrent-call guard (C5, H9)

**Files:**
- Modify: `seer-py/src/lib.rs` around `follow_cancel_sender` (lines ~598-631), `cancel_follow` (~649-654).

- [ ] **Step C3.1: Replace `.expect(...)` with poison-tolerant acquisition everywhere**

```rust
fn lock_follow() -> std::sync::MutexGuard<'static, watch::Sender<bool>> {
    follow_cancel_sender()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}
```

- [ ] **Step C3.2: Add a concurrent-call guard**

```rust
static FOLLOW_ACTIVE: AtomicBool = AtomicBool::new(false);

#[pyfunction]
fn dns_follow(py: Python<'_>, ...) -> PyResult<...> {
    if FOLLOW_ACTIVE.compare_exchange(false, true, SeqCst, SeqCst).is_err() {
        return Err(PyRuntimeError::new_err(
            "dns_follow is already running; cancel it or wait"
        ));
    }
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) { FOLLOW_ACTIVE.store(false, SeqCst); }
    }
    let _active = ActiveGuard;
    // existing body
}
```

- [ ] **Step C3.3: Test**

```python
# seer-py/tests/test_dns_follow_safety.py
import threading, pytest, seer

def test_concurrent_dns_follow_is_rejected():
    errs = []
    def runner():
        try:
            seer.dns_follow("example.com", max_iterations=1, interval=0.1)
        except RuntimeError as e:
            errs.append(str(e))

    threads = [threading.Thread(target=runner) for _ in range(3)]
    for t in threads: t.start()
    for t in threads: t.join()

    # At least one concurrent call must be rejected with a clear message.
    assert any("already running" in e for e in errs)
```

Gate behind live-network flag.

- [ ] **Step C3.4: Commit**

```
git add seer-py/src/lib.rs seer-py/tests/test_dns_follow_safety.py
git commit -m "fix(py): guard dns_follow against concurrent calls and mutex poison"
```

### Task C4: Wire sanitized_message at PyO3 error sites (H8)

Already covered by Task C2's `seer_err_to_py`. Verify all sites route through it.

- [ ] **Step C4.1:** Grep for `e.to_string()` in seer-py/src/lib.rs; each must become `seer_err_to_py(&e)` or an explicit `e.sanitized_message()`.

- [ ] **Step C4.2: Commit**

If any additional changes:
```
git add seer-py/src/lib.rs
git commit -m "fix(py): route all SeerError marshaling through sanitized_message"
```

### Task C5: json_to_python recursion cap (M3)

**Files:**
- Modify: `seer-py/src/lib.rs:717-748`.

- [ ] **Step C5.1: Add depth parameter**

```rust
const MAX_JSON_DEPTH: usize = 128;

fn json_to_python(py: Python<'_>, v: &Value, depth: usize) -> PyResult<PyObject> {
    if depth > MAX_JSON_DEPTH {
        return Err(PyValueError::new_err(
            format!("JSON structure exceeds max depth {MAX_JSON_DEPTH}")
        ));
    }
    match v {
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for x in arr {
                list.append(json_to_python(py, x, depth + 1)?)?;
            }
            Ok(list.into())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_to_python(py, v, depth + 1)?)?;
            }
            Ok(dict.into())
        }
        // existing leaf cases
    }
}
```

- [ ] **Step C5.2: Update all callers to pass `depth=0`.**

- [ ] **Step C5.3: Test**

Construct a `serde_json::Value` with 200 levels of nesting in Rust, expose a tiny `#[pyfunction]` under `#[cfg(test)]` to trigger it, and assert it raises ValueError rather than aborting.

Alternative: test by feeding a crafted JSON string through an entry point that uses `json_to_python`, if one exists.

- [ ] **Step C5.4: Commit**

```
cd seer-py && maturin develop --release
pytest 2>&1 | tail -10
git add seer-py/src/lib.rs
git commit -m "fix(py): cap json_to_python recursion at 128 levels"
```

### Task C6: Decouple progress callback from Tokio workers (H7)

**Files:**
- Modify: `seer-py/src/lib.rs:269-282` (progress callback builder).

- [ ] **Step C6.1: Use a `std::sync::mpsc` drained by a Python thread**

Rather than `Python::with_gil(...)` on the Tokio worker, send `ProgressEvent { completed, total, domain }` through a channel. Spawn a dedicated Python-side drainer thread that owns the GIL when needed and calls the callback.

Concrete:
```rust
struct ProgressPipe {
    tx: std::sync::mpsc::SyncSender<ProgressEvent>,
}

impl ProgressPipe {
    fn new(py_cb: PyObject) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<ProgressEvent>(1024);
        std::thread::spawn(move || {
            while let Ok(ev) = rx.recv() {
                Python::with_gil(|py| {
                    let _ = py_cb.call1(py, (ev.completed, ev.total, ev.domain));
                });
            }
        });
        Self { tx }
    }
}
```

The Rust-side `ProgressCallback` just sends into the channel and returns — never touches the GIL.

- [ ] **Step C6.2: Test**

Add a test that runs `bulk_whois` with a callback that sleeps 500ms inside, confirm it finishes and progress fires at least once (not deadlocks).

- [ ] **Step C6.3: Commit**

```
git add seer-py/src/lib.rs
git commit -m "fix(py): decouple progress callback from tokio workers to avoid GIL deadlock"
```

### Task C7: Move RDAP auto-routing into Rust (M4)

**Files:**
- Modify: `seer-core/src/rdap/mod.rs` — add `pub async fn auto_lookup(query: &str) -> Result<RdapResult>`.
- Modify: `seer-py/src/lib.rs` — add `rdap_auto` binding.
- Modify: `seer-py/python/seer/__init__.py:92-125` — delegate `rdap()` to `rdap_auto`, remove `int()` ASN sniffing.

- [ ] **Step C7.1: Implement auto_lookup**

Logic: if `query` parses as `IpAddr`, call `rdap_ip`. If `query` starts with `AS` (case-insensitive) and the rest is pure digits, call `rdap_asn`. Otherwise call `rdap_domain`.

- [ ] **Step C7.2: Test**

```rust
#[test]
fn auto_lookup_routes_ip_v4() { /* ... */ }
#[test]
fn auto_lookup_routes_asn() { /* ... */ }
#[test]
fn auto_lookup_routes_domain_as_prefix() {
    // Regression for the as1234.io bug: this must route as a domain.
}
```

- [ ] **Step C7.3: Commit**

```
git add seer-core/src/rdap/ seer-py/src/lib.rs seer-py/python/seer/__init__.py
git commit -m "fix(py): move RDAP auto-routing into core to fix AS-prefix domain misroute"
```

### Task C8: .venv removal (M5)

Covered in Task 0.3. Already committed at pre-flight.

---

## Batch D: API Hardening

### Task D1: Default to loopback + fix lifespan warning (C6)

**Files:**
- Modify: `seer-api/seer_api/main.py:55-59, 175`.

- [ ] **Step D1.1: Change run() default**

```python
def run() -> None:
    host = os.environ.get("SEER_HOST", "127.0.0.1")
    port = int(os.environ.get("SEER_PORT", "8000"))
    uvicorn.run("seer_api.main:app", host=host, port=port)
```

- [ ] **Step D1.2: Make lifespan warning fire on any non-loopback bind OR missing API key**

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    host = os.environ.get("SEER_HOST", "127.0.0.1")
    if host != "127.0.0.1" and not API_KEY:
        logger.error(
            "seer-api is bound to %s with no SEER_API_KEY set. "
            "Refusing to start. Set SEER_API_KEY or SEER_HOST=127.0.0.1.",
            host,
        )
        raise RuntimeError("refusing to start: public bind without auth")
    yield
```

Yes, this is a hard fail-closed — you explicitly approved it.

- [ ] **Step D1.3: Update README and CLAUDE.md note**

Document the default change in the project's top-level CLAUDE.md and README.md for seer.

- [ ] **Step D1.4: Test**

```python
def test_refuses_public_bind_without_auth(monkeypatch):
    monkeypatch.setenv("SEER_HOST", "0.0.0.0")
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass  # lifespan runs on startup
```

- [ ] **Step D1.5: Commit**

```
git add seer-api/seer_api/main.py seer-api/tests/test_hardening.py
git commit -m "fix(api): default to 127.0.0.1; refuse public bind without SEER_API_KEY

BREAKING: Prior default was 0.0.0.0 with optional API key. New default
is loopback. Operators who relied on public bind must now set both
SEER_HOST and SEER_API_KEY explicitly."
```

### Task D2: Request body size limit (M6)

**Files:**
- Modify: `seer-api/seer_api/main.py` — register ContentSizeLimitMiddleware.

- [ ] **Step D2.1: Add middleware**

```python
class MaxBodySizeMiddleware:
    def __init__(self, app, max_bytes: int = 65536):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl and int(cl) > self.max_bytes:
            await send({"type": "http.response.start", "status": 413, "headers": []})
            await send({"type": "http.response.body", "body": b"payload too large"})
            return
        # Also bound chunked: count bytes as we read.
        total = 0
        async def receive_wrapper():
            nonlocal total
            msg = await receive()
            if msg.get("type") == "http.request":
                total += len(msg.get("body") or b"")
                if total > self.max_bytes:
                    return {"type": "http.request", "body": b"", "more_body": False}
            return msg
        await self.app(scope, receive_wrapper, send)
```

Register via `app.add_middleware(MaxBodySizeMiddleware, max_bytes=65536)`.

- [ ] **Step D2.2: Test**

```python
def test_large_body_rejected(client):
    resp = client.post("/bulk/lookup", json={"domains": ["a.com"] * 100000})
    assert resp.status_code == 413
```

- [ ] **Step D2.3: Commit**

```
git add seer-api/seer_api/main.py seer-api/tests/test_hardening.py
git commit -m "fix(api): cap request body at 64KB to prevent DoS via oversized payload"
```

### Task D3: X-Forwarded-For socket-peer allowlist (H11)

**Files:**
- Modify: `seer-api/seer_api/limiting.py:14-27`.

- [ ] **Step D3.1: Read trusted-proxy list from env**

```python
_TRUSTED_PROXIES = {
    ip.strip()
    for ip in os.environ.get("SEER_TRUSTED_PROXY_IPS", "").split(",")
    if ip.strip()
}

def get_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if os.environ.get("SEER_TRUST_PROXY") == "true":
        if peer in _TRUSTED_PROXIES:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                return xff.split(",")[0].strip()
        # Not from a trusted peer — ignore XFF.
    return peer
```

- [ ] **Step D3.2: Test**

```python
def test_xff_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1")
    # Simulate a request from 203.0.113.5 with spoofed XFF: the limiter
    # should treat it as 203.0.113.5, not 1.2.3.4.
```

- [ ] **Step D3.3: Commit**

```
git add seer-api/seer_api/limiting.py seer-api/tests/test_hardening.py
git commit -m "fix(api): require socket-peer allowlist to trust X-Forwarded-For"
```

### Task D4: /metrics uses socket peer for localhost gate (H12)

**Files:**
- Modify: `seer-api/seer_api/main.py:152-168`.

- [ ] **Step D4.1: Bypass get_client_ip for metrics**

```python
@app.get("/metrics")
@limiter.limit("10/minute")  # was exempt — now bounded
async def metrics(request: Request):
    peer = request.client.host if request.client else ""
    if peer not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=403, detail="metrics restricted to localhost")
    return dict(endpoint_counts)
```

- [ ] **Step D4.2: Commit**

```
git add seer-api/seer_api/main.py
git commit -m "fix(api): gate /metrics on socket peer, rate-limit it"
```

### Task D5: Gate /docs, /redoc, /openapi.json (H14)

**Files:**
- Modify: `seer-api/seer_api/main.py` — remove from `_AUTH_EXEMPT_PATHS`.

- [ ] **Step D5.1: Remove from the exempt list.**

- [ ] **Step D5.2: Add optional `SEER_DOCS_ENABLED` env var**

```python
DOCS_ENABLED = os.environ.get("SEER_DOCS_ENABLED", "false").lower() == "true"
app = FastAPI(
    ...,
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)
```

- [ ] **Step D5.3: Test**

```python
def test_docs_off_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
```

- [ ] **Step D5.4: Commit**

```
git add seer-api/seer_api/main.py seer-api/tests/test_hardening.py
git commit -m "fix(api): disable docs/openapi by default; gate behind SEER_DOCS_ENABLED"
```

### Task D6: Sanitize SSE streaming errors (H13)

**Files:**
- Modify: `seer-api/seer_api/streaming.py:88-93`.

- [ ] **Step D6.1: Route through safe_error_message**

```python
from .errors import safe_error_message

yield _sse("error", {"message": safe_error_message(pending_error, fallback="bulk operation failed")})
logger.exception("streaming bulk failure", exc_info=pending_error)
```

- [ ] **Step D6.2: Test**

Add a test that forces an internal exception and asserts the SSE event does NOT contain file paths, Python tracebacks, or URLs.

- [ ] **Step D6.3: Commit**

```
git add seer-api/seer_api/streaming.py seer-api/tests/test_streaming.py
git commit -m "fix(api): sanitize SSE error events before sending to clients"
```

### Task D7: Require shared rate-limit store for multi-worker (H10)

**Files:**
- Modify: `seer-api/seer_api/limiting.py`, `main.py`.

- [ ] **Step D7.1: Detect multi-worker + in-memory store at startup**

In the lifespan:
```python
workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
if workers > 1 and _storage_uri == "memory://":
    raise RuntimeError(
        "multi-worker deployment requires SEER_RATELIMIT_STORAGE_URI "
        "(e.g. redis://host:6379). Refusing to start with an in-memory "
        "limiter that would be bypassed per-worker."
    )
```

- [ ] **Step D7.2: Commit**

```
git add seer-api/seer_api/main.py
git commit -m "fix(api): refuse multi-worker startup without shared rate-limit store"
```

### Task D8: Typed exception classification in safe_error_message (M8)

**Files:**
- Modify: `seer-api/seer_api/errors.py:12-43`.

- [ ] **Step D8.1: Switch from keyword matching to exception-type matching**

```python
def safe_error_message(exc: BaseException, fallback: str = "Request failed") -> str:
    if isinstance(exc, ValueError):
        return str(exc)[:200]  # validation errors are already sanitized
    if isinstance(exc, TimeoutError):
        return "request timed out"
    if isinstance(exc, ConnectionError):
        return "upstream connection failed"
    # Fall back only for unknown — no substring sniffing of message contents
    return fallback

def http_status_for(exc: BaseException) -> int:
    if isinstance(exc, ValueError):
        return 400
    if isinstance(exc, TimeoutError):
        return 504
    if isinstance(exc, ConnectionError):
        return 502
    return 500
```

Update callers to use `http_status_for(exc)` where they previously hardcoded 500.

- [ ] **Step D8.2: Test**

```python
def test_timeout_returns_504():
    # Raise TimeoutError via a mocked seer and verify response code.
```

- [ ] **Step D8.3: Commit**

```
git add seer-api/seer_api/errors.py
git commit -m "fix(api): classify errors by type, not substring match"
```

### Task D9: Rate-limit /metrics (M9)

Already covered by Task D4 (`@limiter.limit("10/minute")`).

---

## Batch E: Test Coverage

### Task E1: DNS resolver unit tests (C8 part 1)

**Files:**
- Modify: `seer-core/src/dns/resolver.rs` — add `#[cfg(test)] mod tests`.

- [ ] **Step E1.1: Add tests that mock the hickory resolver**

At minimum:
- `RecordType::from_str` edge cases (lowercase, whitespace, unknown type).
- `normalize_domain` applied before resolution.
- Resolver returns empty → proper error variant.

Without mocking hickory directly (complex), at least cover `RecordType` parsing and `DnsRecord` serialization thoroughly.

- [ ] **Step E1.2: Commit**

```
cargo test -p seer-core dns::resolver 2>&1 | tail -10
git add seer-core/src/dns/resolver.rs
git commit -m "test(core): add unit tests for DNS record parsing"
```

### Task E2: Availability decision tests (M11)

**Files:**
- Modify: `seer-core/src/availability.rs` — test `check()` decision matrix.

- [ ] **Step E2.1: Table-driven test**

```rust
#[test]
fn availability_decisions() {
    let cases = vec![
        (/* whois present, rdap absent */, Availability::Taken),
        (/* both absent, NXDOMAIN */,    Availability::Available),
        (/* timeout */,                    Availability::Unknown),
        // etc.
    ];
    for (input, expected) in cases {
        assert_eq!(check(input), expected);
    }
}
```

- [ ] **Step E2.2: Commit**

```
cargo test -p seer-core availability 2>&1 | tail -10
git add seer-core/src/availability.rs
git commit -m "test(core): cover availability.check decision matrix"
```

### Task E3: Gate live-network tests (C8 part 2, M10)

**Files:**
- Modify: `seer-core/src/dns/dnssec.rs:607-643`, `seer-core/src/dns/follow.rs:341-416`, and any other live-network tests surfaced by grep.
- Modify: `seer-api/tests/test_streaming.py`, `seer-py/tests/test_bulk_progress.py`.

- [ ] **Step E3.1: Rust — add `#[ignore = "live network"]` to any test touching external DNS/HTTP/WHOIS**

```
grep -rn 'cloudflare\|wikipedia\|iana\|google\.com\|example\.com' seer-core/src/ --include='*.rs'
```
For each test that makes an actual call, add `#[ignore]`.

Document in CLAUDE.md and README how to run them: `cargo test --workspace -- --ignored`.

- [ ] **Step E3.2: Python — skip when `SEER_LIVE_TESTS` unset**

```python
LIVE = os.environ.get("SEER_LIVE_TESTS") == "1"

@pytest.mark.skipif(not LIVE, reason="live network test")
def test_sse_bulk_progress():
    ...
```

- [ ] **Step E3.3: Add hermetic replacements**

For `test_streaming.py`, mock `seer.bulk_lookup` to return synthetic results and verify SSE framing only. For `test_bulk_progress.py`, similarly mock.

- [ ] **Step E3.4: Commit**

```
git add seer-core/src/dns/ seer-api/tests/ seer-py/tests/
git commit -m "test: gate live-network tests behind opt-in flag; add hermetic coverage"
```

### Task E4: Fix flaky cache test (M12)

**Files:**
- Modify: `seer-core/src/cache.rs:509-528`.

- [ ] **Step E4.1: Use a `tokio::time::pause()` / `advance()` instead of real sleep**

```rust
#[tokio::test(start_paused = true)]
async fn test_needs_refresh() {
    let cache = TtlCache::new(Duration::from_secs(1));
    cache.insert("k", "v");
    tokio::time::advance(Duration::from_millis(800)).await;
    assert!(cache.get("k").is_some());
    tokio::time::advance(Duration::from_millis(300)).await;
    assert!(cache.get("k").is_none());
}
```

- [ ] **Step E4.2: Commit**

```
cargo test -p seer-core cache 2>&1 | tail -10
git add seer-core/src/cache.rs
git commit -m "test(core): use tokio pause/advance to deflake cache TTL test"
```

### Task E5: Generic WHOIS parser fixtures (M13)

**Files:**
- Modify: `seer-core/src/whois/parsers/generic.rs:38-58`.

- [ ] **Step E5.1: Add fixture tests for real-world formats**

Cover: GDPR-redacted (.com post-2018), CRLF line endings, current Verisign thick, numeric-only date formats.

Store sample responses inline in `tests` module or under `seer-core/tests/fixtures/whois/`.

- [ ] **Step E5.2: Commit**

```
cargo test -p seer-core whois::parsers::generic 2>&1 | tail -10
git add seer-core/src/whois/parsers/generic.rs seer-core/tests/fixtures/
git commit -m "test(core): add real-world gTLD WHOIS fixtures to generic parser"
```

---

## Task F: Final Validation + PR

- [ ] **Step F.1: Workspace-wide checks**

```
cd /home/zac/Projects/arcanum_suite/seer
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -50
cargo test --workspace 2>&1 | tail -30
```
Expected: green on all three.

- [ ] **Step F.2: Python checks**

```
cd seer-py && maturin develop --release && pytest 2>&1 | tail -20
cd ../seer-api && pytest 2>&1 | tail -20
```

- [ ] **Step F.3: Live-network smoke test (optional, manual)**

```
SEER_LIVE_TESTS=1 pytest -k bulk_progress
cargo test --workspace -- --ignored 2>&1 | tail -20
```

- [ ] **Step F.4: Verify branch commit log is clean**

```
git log --oneline main..HEAD
```
Expected: ~25 commits, each conventional-commit formatted.

- [ ] **Step F.5: Push branch and open PR**

```
git push -u origin HEAD
gh pr create --title "fix: adversarial review remediation (SSRF, async safety, API hardening)" \
  --body "$(cat <<'EOF'
## Summary
Remediates 35 findings from adversarial code review:
- 8 Critical (SSRF, async-Drop mutex, process-abort through FFI, open-by-default API)
- 14 High (WHOIS hostname SSRF, MITM cert policy, RDAP recursion, retry classifier, rate-limit bypass, docs leak, ...)
- 13 Medium (file corruption, .expect in library code, recursion caps, test gaps)

## Breaking changes
- `seer-api` now defaults to `127.0.0.1`. Public bind requires `SEER_API_KEY` **and** explicit `SEER_HOST`.
- `/docs`, `/redoc`, `/openapi.json` are disabled by default; set `SEER_DOCS_ENABLED=true` to enable.
- Multi-worker deployments must configure `SEER_RATELIMIT_STORAGE_URI` (e.g. Redis).
- `danger_accept_invalid_certs` removed from status HTTP fetch (kept only in SSL inspection path).

## Test plan
- [x] `cargo test --workspace` green
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [x] `cd seer-py && pytest` green
- [x] `cd seer-api && pytest` green
- [ ] `cargo test --workspace -- --ignored` (live network, manual)
- [ ] `SEER_LIVE_TESTS=1 pytest` (live network, manual)
EOF
)"
```

---

## Self-Review Checklist

Running through the 35 findings from the review against the plan:

| # | Finding | Task |
|---|---------|------|
| C1 | lookup.rs Drop blocking Mutex | B1 |
| C2 | lookup.rs `.expect()` poisoning | B1 |
| C3 | subdomains.rs buffered body | B4 |
| C4 | block_on in async → FFI abort | C2 |
| C5 | follow_cancel_sender poison | C3 |
| C6 | Open 0.0.0.0 default | D1 |
| C7 | SSRF no blocklist | A1-A5 |
| C8 | Test gaps (DNS resolver, live net) | E1, E3 |
| H1 | WHOIS referral hostname SSRF | A2 |
| H2 | danger_accept_invalid_certs HTTP | B7 |
| H3 | RdapEntity recursion | B3 |
| H4 | Bootstrap body no timeout | B2 |
| H5 | RetryExhausted classifier | B6 |
| H6 | abi3-py39 not default | C1 |
| H7 | with_gil on Tokio worker | C6 |
| H8 | to_string bypasses sanitize | C2/C4 |
| H9 | dns_follow concurrent race | C3 |
| H10 | Rate-limit per-worker | D7 |
| H11 | X-Forwarded-For trust | D3 |
| H12 | /metrics spoofable IP | D4 |
| H13 | SSE error leak | D6 |
| H14 | /docs open | D5 |
| M1 | .expect in library statics | B5 |
| M2 | Corrupt history silent loss | B8 |
| M3 | json_to_python unbounded | C5 |
| M4 | Python-side RDAP routing | C7 |
| M5 | .venv in tree | Task 0.3 |
| M6 | No body size limit | D2 |
| M7 | MCP SSRF | A5 |
| M8 | safe_error_message substring | D8 |
| M9 | /metrics rate-exempt | D4/D9 |
| M10 | Live-net tests unignored | E3 |
| M11 | Availability tests missing | E2 |
| M12 | Flaky cache test | E4 |
| M13 | Generic parser fixtures | E5 |

All 35 findings are mapped to tasks.
