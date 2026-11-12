//! The response cache: serialized success bodies, reused for a short time.
//!
//! One cache serves every route, because the value is the response body
//! itself. Only successes are stored, so an error response is never
//! replayed. (A lookup that *succeeds* in reporting a problem — a DNS
//! SERVFAIL, a status report with a failed part — is a success and is
//! reused like any other.) With a TTL of zero there is no cache and
//! successes are marked `no-store`.
//!
//! A keyed caller's success is marked `private`: this cache serves both
//! tiers (the gate runs first), but a shared cache in front must not store
//! what only keyed callers may have.
//!
//! Memory is bounded by entries times body size: at most `CAPACITY`
//! bodies of at most `MAX_BODY` bytes each. A larger body is served but
//! not kept, so what a caller's own zone or registry returns cannot set
//! this server's memory use.

use std::time::Duration;

use axum::body::Bytes;
use axum::http::HeaderValue;
use seer_core::TtlCache;

use crate::tier::Caller;

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
    /// `Cache-Control` for an anonymous caller's success.
    shared: HeaderValue,
    /// `Cache-Control` for a keyed caller's success.
    private: HeaderValue,
}

impl ResponseCache {
    /// A cache whose entries live for `ttl`; zero disables it.
    pub fn new(ttl: Duration) -> Self {
        let no_store = || HeaderValue::from_static("no-store");
        if ttl.is_zero() {
            return Self {
                entries: None,
                shared: no_store(),
                private: no_store(),
            };
        }
        // The same lifetime as the entry, so whoever may reuse the
        // response reuses it for as long as this server would. Digits
        // always form a valid header value; the fallbacks exist only
        // because library code may not `unwrap`.
        let secs = ttl.as_secs();
        Self {
            entries: Some(TtlCache::with_max_capacity(ttl, CAPACITY)),
            shared: HeaderValue::from_str(&format!("max-age={secs}"))
                .unwrap_or_else(|_| no_store()),
            private: HeaderValue::from_str(&format!("private, max-age={secs}"))
                .unwrap_or_else(|_| no_store()),
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

    /// The `Cache-Control` value for a success sent to `caller`. An
    /// anonymous caller's may be stored by a proxy or CDN in front
    /// (`max-age=<ttl>`); a keyed caller's only by that caller
    /// (`private, max-age=<ttl>`), because it may be an answer anonymous
    /// callers are not allowed. `no-store` when the cache is disabled.
    pub fn cache_control(&self, caller: Caller) -> HeaderValue {
        match caller {
            Caller::Anonymous => self.shared.clone(),
            Caller::Keyed => self.private.clone(),
        }
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
        assert_eq!(cache.cache_control(Caller::Anonymous), "max-age=60");
    }

    #[test]
    fn a_zero_ttl_disables_the_cache() {
        let cache = ResponseCache::new(Duration::ZERO);
        cache.put("k".to_string(), Bytes::from_static(b"1"));
        assert_eq!(cache.get("k"), None);
        assert_eq!(cache.cache_control(Caller::Anonymous), "no-store");
    }

    #[test]
    fn a_keyed_callers_answer_is_private() {
        let cache = ResponseCache::new(Duration::from_secs(60));
        assert_eq!(cache.cache_control(Caller::Anonymous), "max-age=60");
        assert_eq!(cache.cache_control(Caller::Keyed), "private, max-age=60");
        // Disabled: nobody stores anything.
        let off = ResponseCache::new(Duration::ZERO);
        assert_eq!(off.cache_control(Caller::Keyed), "no-store");
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
