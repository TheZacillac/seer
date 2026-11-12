//! The response cache: serialized success bodies, reused for a short time.
//!
//! One cache serves every route, because the value is the response body
//! itself. Only successes are stored, so an error response is never
//! replayed. (A lookup that *succeeds* in reporting a problem — a DNS
//! SERVFAIL, a status report with a failed part — is a success and is
//! reused like any other.) With a TTL of zero there is no cache and
//! successes are marked `no-store`.
//!
//! Memory is bounded by entries times body size: at most `CAPACITY`
//! bodies of at most `MAX_BODY` bytes each. A larger body is served but
//! not kept, so what a caller's own zone or registry returns cannot set
//! this server's memory use.

use std::time::Duration;

use axum::body::Bytes;
use axum::http::HeaderValue;
use seer_core::TtlCache;

/// Most responses kept at once. Past it, expired entries are purged and
/// then the oldest evicted (`TtlCache`'s policy).
const CAPACITY: usize = 2_048;

/// Largest body kept. Ordinary lookup, WHOIS, RDAP and DNS answers are a
/// few kilobytes; with `CAPACITY` this caps the cache at 128 MiB.
const MAX_BODY: usize = 64 * 1024;

// Checked at compile time: raising either constant past a quarter of a
// gigabyte in total has to be a deliberate edit here.
const _: () = assert!(MAX_BODY * CAPACITY <= 256 * 1024 * 1024);

/// Separates a route from its parts, and parts from each other, in a key.
/// A control character, so it cannot occur in a normalized name.
const SEPARATOR: char = '\u{1f}';

/// Serialized success bodies by request key.
pub struct ResponseCache {
    /// `None` when the cache is disabled (a TTL of zero).
    entries: Option<TtlCache<String, Bytes>>,
    cache_control: HeaderValue,
}

impl ResponseCache {
    /// A cache whose entries live for `ttl`; zero disables it.
    pub fn new(ttl: Duration) -> Self {
        if ttl.is_zero() {
            return Self {
                entries: None,
                cache_control: HeaderValue::from_static("no-store"),
            };
        }
        Self {
            entries: Some(TtlCache::with_max_capacity(ttl, CAPACITY)),
            // The same lifetime, so a proxy or CDN in front can reuse the
            // response for as long as this server would. Digits always
            // form a valid header value; the fallback exists only because
            // library code may not `unwrap`.
            cache_control: HeaderValue::from_str(&format!("max-age={}", ttl.as_secs()))
                .unwrap_or_else(|_| HeaderValue::from_static("no-store")),
        }
    }

    /// The stored body for `key`, if there is one and it has not expired.
    pub fn get(&self, key: &str) -> Option<Bytes> {
        self.entries.as_ref()?.get(&key.to_string())
    }

    /// Stores a success body. Does nothing when the cache is disabled or
    /// the body is larger than `MAX_BODY`.
    pub fn put(&self, key: String, body: Bytes) {
        if body.len() > MAX_BODY {
            return;
        }
        if let Some(entries) = &self.entries {
            entries.insert(key, body);
        }
    }

    /// The `Cache-Control` value for a success: `max-age=<ttl>`, or
    /// `no-store` when the cache is disabled.
    pub fn cache_control(&self) -> HeaderValue {
        self.cache_control.clone()
    }
}

/// The cache key for a request: its route pattern and the normalized
/// values that select the answer.
pub fn key(route: &str, parts: &[&str]) -> String {
    let mut key = String::from(route);
    for part in parts {
        key.push(SEPARATOR);
        key.push_str(part);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_body_is_returned_until_replaced() {
        let cache = ResponseCache::new(Duration::from_secs(60));
        assert_eq!(cache.get("k"), None);
        cache.put("k".to_string(), Bytes::from_static(b"{\"a\":1}"));
        assert_eq!(cache.get("k"), Some(Bytes::from_static(b"{\"a\":1}")));
        assert_eq!(cache.get("other"), None);
        assert_eq!(cache.cache_control(), "max-age=60");
    }

    #[test]
    fn a_zero_ttl_disables_the_cache() {
        let cache = ResponseCache::new(Duration::ZERO);
        cache.put("k".to_string(), Bytes::from_static(b"1"));
        assert_eq!(cache.get("k"), None);
        assert_eq!(cache.cache_control(), "no-store");
    }

    #[test]
    fn keys_separate_routes_and_parts() {
        assert_eq!(key("/a/{x}", &["one"]), key("/a/{x}", &["one"]));
        assert_ne!(key("/a/{x}", &["one"]), key("/b/{x}", &["one"]));
        assert_ne!(key("/a/{x}", &["one"]), key("/a/{x}", &["two"]));
        // Parts cannot run together into another request's key.
        assert_ne!(key("/a", &["ab", "c"]), key("/a", &["a", "bc"]));
        assert_ne!(key("/a", &["ab", ""]), key("/a", &["a", "b"]));
    }
    #[test]
    fn an_oversized_body_is_not_stored() {
        // The cache is bounded in bytes as well as entries: what a caller's
        // own zone or registry returns must not set its memory use.
        let cache = ResponseCache::new(Duration::from_secs(60));
        cache.put("fits".to_string(), Bytes::from(vec![b'x'; MAX_BODY]));
        cache.put("too-big".to_string(), Bytes::from(vec![b'x'; MAX_BODY + 1]));
        assert!(cache.get("fits").is_some());
        assert_eq!(cache.get("too-big"), None);
    }
}
