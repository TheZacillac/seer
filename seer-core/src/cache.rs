//! TTL-based caching.
//!
//! This module provides a thread-safe, capacity-bounded cache with
//! time-to-live (TTL) expiration.
//!
//! # Clock
//!
//! The cache uses [`tokio::time::Instant`] as its monotonic clock. In normal
//! operation this is identical to [`std::time::Instant`]; when a test runs
//! inside a `#[tokio::test(start_paused = true)]` runtime, the clock becomes
//! virtual and can be advanced deterministically via `tokio::time::advance`,
//! which keeps TTL unit tests fast and non-flaky.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

/// A cache entry with TTL tracking.
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
    ttl: Duration,
}

impl<V> CacheEntry<V> {
    /// Creates a new cache entry.
    fn new(value: V, ttl: Duration) -> Self {
        Self {
            value,
            inserted_at: Instant::now(),
            ttl,
        }
    }

    /// Returns true if the entry has expired.
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }

    /// Returns the age of the entry.
    fn age(&self) -> Duration {
        self.inserted_at.elapsed()
    }
}

/// Thread-safe TTL cache.
///
/// This cache supports:
/// - Automatic expiration based on TTL
/// - A capacity bound (expired, then oldest, entries are evicted)
/// - Thread-safe access via RwLock
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use seer_core::cache::TtlCache;
///
/// let cache: TtlCache<String, String> = TtlCache::new(Duration::from_secs(3600));
///
/// // Insert a value
/// cache.insert("key".to_string(), "value".to_string());
///
/// // Get the value (returns None if expired)
/// if let Some(value) = cache.get(&"key".to_string()) {
///     println!("Got: {}", value);
/// }
/// ```
pub struct TtlCache<K, V> {
    entries: RwLock<HashMap<K, CacheEntry<V>>>,
    default_ttl: Duration,
    /// Maximum number of entries. When exceeded, expired entries are purged
    /// and if still over capacity, the oldest entry is evicted.
    max_capacity: usize,
}

/// Default maximum capacity for TtlCache instances.
const DEFAULT_MAX_CAPACITY: usize = 1024;

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    V: Clone,
{
    /// Creates a new cache with the specified default TTL and default max capacity (1024).
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
            max_capacity: DEFAULT_MAX_CAPACITY,
        }
    }

    /// Creates a new cache with a specified TTL and max capacity.
    pub fn with_max_capacity(default_ttl: Duration, max_capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
            max_capacity,
        }
    }

    /// Read access; a poisoned lock is recovered with a warning.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<K, CacheEntry<V>>> {
        self.entries.read().unwrap_or_else(|poisoned| {
            warn!("Cache read lock poisoned, recovering");
            poisoned.into_inner()
        })
    }

    /// Write access; a poisoned lock is recovered with a warning.
    fn write(&self) -> RwLockWriteGuard<'_, HashMap<K, CacheEntry<V>>> {
        self.entries.write().unwrap_or_else(|poisoned| {
            warn!("Cache write lock poisoned, recovering");
            poisoned.into_inner()
        })
    }

    /// Gets a value from the cache if it exists and is not expired.
    ///
    /// Returns `None` if the key doesn't exist or the entry has expired.
    pub fn get(&self, key: &K) -> Option<V> {
        let entries = self.read();
        let entry = entries.get(key)?;

        if entry.is_expired() {
            debug!(
                hit = false,
                ?key,
                age_secs = entry.age().as_secs(),
                "cache lookup (expired)"
            );
            None
        } else {
            debug!(hit = true, ?key, "cache lookup");
            Some(entry.value.clone())
        }
    }

    /// Inserts a value into the cache with the default TTL.
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Inserts a value into the cache with a custom TTL.
    ///
    /// If the cache exceeds max capacity, expired entries are purged first.
    /// If still over capacity, the oldest entry is evicted.
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let mut entries = self.write();

        // Evict if at capacity (before inserting)
        if entries.len() >= self.max_capacity && !entries.contains_key(&key) {
            // First, remove expired entries
            let before = entries.len();
            entries.retain(|_, entry| !entry.is_expired());
            let removed = before - entries.len();
            if removed > 0 {
                debug!(removed, "Evicted expired entries to make room");
            }

            // If still at capacity, evict the oldest entries in a single batch
            // down to a low-water mark (~90% of capacity). Doing this in one
            // pass amortizes the O(n) selection across the next inserts instead
            // of re-running it on every insert once full — which serialized all
            // writers behind an O(n) scan and became a write-lock contention
            // cliff at large capacities (issue #51). Exact-LRU is preserved:
            // the genuinely oldest entries are the ones removed.
            if entries.len() >= self.max_capacity {
                let low_water = self.max_capacity.saturating_mul(9) / 10;
                let to_remove = entries.len().saturating_sub(low_water).max(1);
                let mut aged: Vec<(K, Duration)> =
                    entries.iter().map(|(k, e)| (k.clone(), e.age())).collect();
                let take = to_remove.min(aged.len());
                if take < aged.len() {
                    // Partition the `take` oldest (largest age) to the front; an
                    // O(n) average partial-select, no full sort.
                    aged.select_nth_unstable_by(take - 1, |a, b| b.1.cmp(&a.1));
                }
                for (k, _) in aged.into_iter().take(take) {
                    entries.remove(&k);
                }
                debug!(evicted = take, "Batch-evicted oldest entries to make room");
            }
        }

        debug!(?key, ttl_secs = ttl.as_secs(), "Inserting cache entry");
        entries.insert(key, CacheEntry::new(value, ttl));
    }

    /// Removes a value from the cache.
    pub fn remove(&self, key: &K) -> Option<V> {
        self.write().remove(key).map(|e| e.value)
    }

    /// Returns the number of entries in the cache (including expired ones).
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        self.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_secs(3600));

        cache.insert("key".to_string(), "value".to_string());

        assert_eq!(cache.get(&"key".to_string()), Some("value".to_string()));
    }

    #[test]
    fn test_cache_get_missing_key() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_secs(3600));

        assert_eq!(cache.get(&"missing".to_string()), None);
    }

    #[test]
    fn test_cache_expiration() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_millis(10));

        cache.insert("key".to_string(), "value".to_string());
        assert_eq!(cache.get(&"key".to_string()), Some("value".to_string()));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(cache.get(&"key".to_string()), None);
    }

    #[test]
    fn test_cache_remove() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_secs(3600));

        cache.insert("key".to_string(), "value".to_string());
        assert!(cache.get(&"key".to_string()).is_some());

        cache.remove(&"key".to_string());
        assert!(cache.get(&"key".to_string()).is_none());
    }

    #[test]
    fn capacity_eviction_batches_to_low_water_mark() {
        // Eviction removes a BATCH of the oldest entries down to a low-water
        // mark in a single pass, so the O(n) selection is amortized across the
        // next inserts rather than re-run on every insert once full (issue #51).
        // After crossing capacity the size drops below it, not hovering at it.
        let cap = 100;
        let cache: TtlCache<u32, u32> = TtlCache::with_max_capacity(Duration::from_secs(3600), cap);
        for i in 0..=cap as u32 {
            // 0..=100 => 101 distinct keys, crossing capacity once.
            cache.insert(i, i);
        }
        assert!(
            cache.len() <= (cap * 9 / 10) + 1,
            "batch eviction should drop to ~90% low-water, got len {}",
            cache.len()
        );
        assert!(
            cache.len() < cap,
            "must be below capacity after a batch evict"
        );
        // Exact-LRU preserved: newest survives, oldest evicted.
        assert_eq!(cache.get(&(cap as u32)), Some(cap as u32));
        assert_eq!(cache.get(&0), None);
    }

    #[test]
    fn capacity_eviction_never_exceeds_capacity_under_churn() {
        let cap = 50;
        let cache: TtlCache<u32, u32> = TtlCache::with_max_capacity(Duration::from_secs(3600), cap);
        for i in 0..1000u32 {
            cache.insert(i, i);
            assert!(cache.len() <= cap, "len {} exceeded cap {cap}", cache.len());
        }
    }

    #[test]
    fn test_cache_clear() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_secs(3600));

        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_entry_expires_after_ttl() {
        // Uses tokio's virtual clock (TtlCache uses tokio::time::Instant), so
        // the clock is advanced deterministically instead of real sleeps.
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_secs(1));
        cache.insert("key".to_string(), "value".to_string());

        tokio::time::advance(Duration::from_millis(800)).await;
        assert!(
            cache.get(&"key".to_string()).is_some(),
            "entry must not be expired at t=800ms (< 1000ms TTL)"
        );

        tokio::time::advance(Duration::from_millis(300)).await;
        assert!(
            cache.get(&"key".to_string()).is_none(),
            "entry must be expired at t=1100ms (> 1000ms TTL)"
        );
    }
}
