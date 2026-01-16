# Security and Bug Audit Report

**Project**: Seer - Domain Name Utility Tool
**Date**: 2026-01-16
**Auditor**: Automated Security Scan
**Severity Levels**: 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info

---

## Executive Summary

This security audit analyzed the Seer codebase (Rust core + Python API) for security vulnerabilities, code quality issues, and potential bugs. The codebase demonstrates good security practices overall, with proper error handling and input validation in most areas. However, several issues were identified that should be addressed.

### Summary Statistics

- **Critical Issues**: 0
- **High Severity**: 1 (SSRF vulnerability)
- **Medium Severity**: 2 (Unwrap calls, missing validation)
- **Low Severity**: 21 (Clippy warnings)
- **Informational**: 5 (Best practices)

---

## Security Vulnerabilities

### 🟠 HIGH: Server-Side Request Forgery (SSRF) Risk

**Location**: `seer-core/src/status/client.rs:78-119`, `seer-core/src/status/client.rs:122-154`

**Description**: The `StatusClient` makes HTTP and TLS connections to user-supplied domains without validating against internal IP addresses or private network ranges. This could allow attackers to:
- Scan internal networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Access localhost services (127.0.0.1, ::1)
- Probe link-local addresses (169.254.0.0/16)
- Access cloud metadata services (169.254.169.254)

**Affected Code**:
```rust
// seer-core/src/status/client.rs:78
async fn fetch_http_info(&self, domain: &str) -> Result<(u16, String, Option<String>)> {
    let url = format!("https://{}", domain);  // ⚠️ No validation against internal IPs
    // ... makes HTTP request to user-supplied domain
}

// seer-core/src/status/client.rs:130
let addr = format!("{}:443", domain);  // ⚠️ No validation
let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
```

**Impact**:
- An attacker could use the API to scan internal networks
- Could access cloud metadata endpoints to steal credentials
- Could fingerprint internal services
- Could bypass firewall restrictions

**Recommendation**:
1. Resolve the domain to IP addresses before making requests
2. Validate that resolved IPs are not in private/internal ranges:
   - 10.0.0.0/8
   - 172.16.0.0/12
   - 192.168.0.0/16
   - 127.0.0.0/8
   - ::1/128
   - fc00::/7
   - fe80::/10
   - 169.254.0.0/16
3. Reject requests to localhost, link-local, and cloud metadata IPs
4. Consider implementing a DNS rebinding protection mechanism

**Example Fix**:
```rust
use std::net::IpAddr;

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() ||
            ipv4.is_loopback() ||
            ipv4.is_link_local() ||
            ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254  // Cloud metadata
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() ||
            (ipv6.segments()[0] & 0xfe00) == 0xfc00 ||  // Unique local
            (ipv6.segments()[0] & 0xffc0) == 0xfe80     // Link local
        }
    }
}

async fn validate_domain_safe(domain: &str) -> Result<()> {
    let ips = tokio::net::lookup_host(format!("{}:443", domain)).await?;
    for socket_addr in ips {
        if is_private_ip(&socket_addr.ip()) {
            return Err(SeerError::InvalidDomain(
                format!("Domain resolves to private IP: {}", socket_addr.ip())
            ));
        }
    }
    Ok(())
}
```

---

### 🟡 MEDIUM: Potential Panic from unwrap() Calls

**Location**: Multiple files

**Description**: While most error handling is proper, several `unwrap()` calls exist that could cause panics if assumptions are violated.

**Affected Files**:
1. `seer-cli/src/repl/mod.rs:367` - Progress bar template
2. `seer-cli/src/display/spinner.rs:15` - Spinner template
3. `seer-core/src/output/human.rs:374` - HashMap lookup
4. `seer-core/src/whois/client.rs:214-219` - Test code (acceptable)

**Impact**:
- Server crashes if hardcoded templates are invalid
- Unexpected panics in production

**Recommendation**:
Replace `unwrap()` with proper error handling:

```rust
// Bad
let style = indicatif::ProgressStyle::default_bar()
    .template("{spinner:.green} [{bar:40}]")
    .unwrap();  // ❌ Can panic

// Good
let style = indicatif::ProgressStyle::default_bar()
    .template("{spinner:.green} [{bar:40}]")
    .expect("Progress bar template is hardcoded and should be valid");  // ✅ Better

// Or handle gracefully
let style = indicatif::ProgressStyle::default_bar()
    .template("{spinner:.green} [{bar:40}]")
    .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar());  // ✅ Best
```

---

### 🟡 MEDIUM: Domain Validation Inconsistency

**Location**: `seer-core/src/whois/client.rs:160-183` vs `seer-core/src/status/client.rs:180-189`

**Description**: Two different domain normalization functions exist with different validation levels:
- `whois/client.rs` has strong validation (checks for alphanumeric, dots, hyphens)
- `status/client.rs` has weak validation (only normalizes, no validation)

**Affected Code**:
```rust
// whois/client.rs - Good validation ✅
let valid = domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
if !valid {
    return Err(SeerError::InvalidDomain(domain.to_string()));
}

// status/client.rs - No validation ❌
fn normalize_domain(domain: &str) -> String {
    // Just normalization, no validation
    domain.strip_prefix("www.").unwrap_or(domain).to_string()
}
```

**Impact**:
- Inconsistent input validation across modules
- Could lead to unexpected behavior or errors downstream

**Recommendation**:
1. Create a single shared `normalize_and_validate_domain()` function in `seer-core/src/lib.rs`
2. Use it consistently across all modules
3. Apply validation before any network operations

---

## Code Quality Issues (Clippy Warnings)

### 🟢 LOW: 21 Clippy Warnings

**Description**: Clippy identified 21 code quality issues that don't affect security but reduce code quality.

#### Summary by Category:

**1. Needless Borrows (3 instances)**
- `seer-core/src/rdap/client.rs:341`
- `seer-core/src/status/client.rs:187`
- `seer-core/src/whois/client.rs:166`

```rust
// Bad
let domain = domain.split('/').next().unwrap_or(&domain);

// Good
let domain = domain.split('/').next().unwrap_or(domain);
```

**2. Manual Range Contains (2 instances)**
- `seer-core/src/output/human.rs:593`
- `seer-core/src/output/human.rs:595`

```rust
// Bad
if status >= 200 && status < 300 {

// Good
if (200..300).contains(&status) {
```

**3. Collapsible If Statements (2 instances)**
- `seer-core/src/rdap/types.rs:139-143`
- `seer-core/src/rdap/types.rs:160-164`

**4. Needless Range Loop (1 instance)**
- `seer-core/src/rdap/client.rs:388`

**5. Other Issues**: Inefficient patterns, unnecessary clones, etc.

**Recommendation**: Run `cargo clippy --fix` to automatically fix most issues.

---

## Best Practices & Informational

### ℹ️ INFO: TLS Certificate Validation Disabled

**Location**: `seer-core/src/status/client.rs:124`

**Description**: Certificate validation is intentionally disabled to check expired/invalid certificates.

```rust
let connector = TlsConnector::builder()
    .danger_accept_invalid_certs(true)  // ℹ️ Intentional for status checking
    .build()
```

**Status**: This is intentional for the status checking feature, but should be documented.

**Recommendation**: Add a comment explaining why this is safe in this context.

---

### ℹ️ INFO: CORS Configuration in Development Mode

**Location**: `seer-api/seer_api/main.py:27-28`

**Description**: Default CORS allows all origins (`*`) in development mode.

```python
else:
    # Development mode: allow all origins but disable credentials
    allowed_origins = ["*"]
    allow_credentials = False
```

**Status**: Acceptable for development, but ensure production sets `SEER_CORS_ORIGINS`.

**Recommendation**: Document in README and add startup warning if running with wildcard CORS.

---

### ℹ️ INFO: No Rate Limiting on API Endpoints

**Location**: All API routers

**Description**: The REST API has no rate limiting at the HTTP layer. Bulk operations have concurrency limits but no per-IP or per-user rate limiting.

**Impact**: Potential for abuse, DoS attacks, or resource exhaustion.

**Recommendation**: Add rate limiting middleware:
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@router.get("/{domain}")
@limiter.limit("100/minute")
async def lookup(request: Request, domain: str):
    # ...
```

---

### ℹ️ INFO: No Dependency Vulnerability Scanner

**Location**: CI/CD pipeline (if exists)

**Description**: The project doesn't appear to have automated dependency vulnerability scanning.

**Recommendation**:
1. Add `cargo audit` to CI/CD pipeline
2. Run `cargo audit` regularly to check for known vulnerabilities
3. Consider using Dependabot or similar for automated updates

**To install and run**:
```bash
cargo install cargo-audit
cargo audit
```

---

### ℹ️ INFO: Bulk Operation Limits

**Location**: `seer-api/seer_api/routers/lookup.py:13-14`

**Description**: Bulk operations have reasonable limits:
- Max 100 domains per request
- Max 50 concurrent operations

**Status**: Good practice ✅

**Recommendation**: Document these limits in API documentation and error messages.

---

## Positive Security Findings ✅

The following security practices are **correctly implemented**:

1. ✅ **No unsafe code blocks** - Zero usage of `unsafe` keyword
2. ✅ **No SQL injection** - No database usage detected
3. ✅ **No command injection** - No shell command execution from user input
4. ✅ **Proper timeout handling** - All network operations have timeouts
5. ✅ **Input validation** - Domain validation in most modules (WHOIS)
6. ✅ **Error handling** - Using Result types and thiserror properly
7. ✅ **No hardcoded secrets** - No passwords or API keys in code
8. ✅ **Limited redirects** - HTTP client limits redirects to 5
9. ✅ **User-Agent header** - HTTP requests identify themselves
10. ✅ **Structured logging** - Using tracing for observability
11. ✅ **Memory safety** - Rust's ownership system prevents memory issues
12. ✅ **Concurrency limits** - Bulk operations use semaphores
13. ✅ **Type safety** - Strong typing throughout
14. ✅ **No eval/exec** - No dynamic code execution
15. ✅ **Safe deserialization** - Using serde with typed structures

---

## Recommendations Summary

### Immediate Actions (Priority: High)

1. **Fix SSRF vulnerability** in status checker (add IP validation)
2. **Replace unwrap() calls** in production code with proper error handling
3. **Unify domain validation** across all modules

### Short-term Actions (Priority: Medium)

4. **Fix all Clippy warnings** by running `cargo clippy --fix`
5. **Add rate limiting** to API endpoints
6. **Document CORS requirements** for production

### Long-term Actions (Priority: Low)

7. **Add cargo-audit** to CI/CD pipeline
8. **Add integration tests** for security scenarios
9. **Implement request logging** with IP addresses
10. **Add OpenAPI security schemes** to document authentication (if added)

---

## Testing Recommendations

### Security Test Cases to Add

1. **SSRF Tests**:
   - Attempt to query localhost
   - Attempt to query private IP ranges
   - Attempt to query cloud metadata endpoints

2. **Input Validation Tests**:
   - Invalid domain formats
   - Extremely long domain names
   - Special characters in domains
   - Unicode/IDN domains

3. **DoS Protection Tests**:
   - Bulk requests with max limits
   - Concurrent request limits
   - Timeout enforcement

4. **Error Handling Tests**:
   - Malformed API responses
   - Network timeouts
   - Invalid SSL certificates

---

## Compliance Notes

- **GDPR**: WHOIS and RDAP data may contain personal information. Consider adding privacy notices.
- **CFAA**: Automated lookups should respect robots.txt and rate limits.
- **Terms of Service**: Ensure compliance with WHOIS server ToS and RDAP registry policies.

---

## Conclusion

The Seer codebase demonstrates **good security practices** overall, particularly in error handling, input validation, and avoiding common vulnerabilities. The primary concern is the **SSRF vulnerability** in the status checker, which should be addressed immediately.

The Rust implementation provides strong memory safety guarantees, and the use of proper error handling patterns (Result types) prevents most common bugs. The code quality issues identified by Clippy are minor and easily fixed.

**Overall Security Rating**: 🟡 **Good with Improvements Needed**

---

## Appendix: How to Run Security Tools

### Clippy (Code Quality)
```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --fix  # Auto-fix issues
```

### Cargo Audit (Dependency Vulnerabilities)
```bash
cargo install cargo-audit
cargo audit
```

### Cargo Deny (Supply Chain Security)
```bash
cargo install cargo-deny
cargo deny check
```

### Format Check
```bash
cargo fmt --check
```

### Test Coverage
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

---

**Report Generated**: 2026-01-16
**Next Review**: Recommend quarterly security audits
