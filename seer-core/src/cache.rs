//! TTL-based caching with stale-while-revalidate semantics.
//!
//! This module provides a thread-safe cache with time-to-live (TTL) expiration
//! and the ability to serve stale data during refresh failures.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;
use std::time::{Duration, Instant};

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

    /// Returns true if the entry is stale (past 75% of TTL).
    /// This is used for stale-while-revalidate logic.
    fn is_stale(&self) -> bool {
        self.inserted_at.elapsed() > (self.ttl * 3 / 4)
    }

    /// Returns the age of the entry.
    fn age(&self) -> Duration {
        self.inserted_at.elapsed()
    }
}

/// Thread-safe TTL cache with stale-while-revalidate semantics.
///
/// This cache supports:
/// - Automatic expiration based on TTL
/// - Serving stale data when fresh data is unavailable
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
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    V: Clone,
{
    /// Creates a new cache with the specified default TTL.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
        }
    }

    /// Gets a value from the cache if it exists and is not expired.
    ///
    /// Returns `None` if the key doesn't exist, the entry has expired,
    /// or the lock is poisoned (with a warning logged).
    pub fn get(&self, key: &K) -> Option<V> {
        let entries = match self.entries.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let entry = entries.get(key)?;

        if entry.is_expired() {
            debug!(?key, age_secs = entry.age().as_secs(), "Cache entry expired");
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Gets a value from the cache even if it's expired.
    ///
    /// This is useful for stale-while-revalidate patterns where you want
    /// to serve stale data while attempting to refresh.
    pub fn get_stale(&self, key: &K) -> Option<V> {
        let entries = match self.entries.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        entries.get(key).map(|entry| {
            if entry.is_expired() {
                debug!(
                    ?key,
                    age_secs = entry.age().as_secs(),
                    "Serving stale cache entry"
                );
            }
            entry.value.clone()
        })
    }

    /// Checks if a key exists and needs refresh (is stale but not expired).
    ///
    /// Returns `true` if the entry exists and is past 75% of its TTL.
    pub fn needs_refresh(&self, key: &K) -> bool {
        let entries = match self.entries.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };

        entries.get(key).is_some_and(|entry| entry.is_stale())
    }

    /// Inserts a value into the cache with the default TTL.
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Inserts a value into the cache with a custom TTL.
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let mut entries = match self.entries.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache write lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        debug!(?key, ttl_secs = ttl.as_secs(), "Inserting cache entry");
        entries.insert(key, CacheEntry::new(value, ttl));
    }

    /// Removes a value from the cache.
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut entries = match self.entries.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache write lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        entries.remove(key).map(|e| e.value)
    }

    /// Removes all expired entries from the cache.
    ///
    /// This is useful for periodic cleanup to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let mut entries = match self.entries.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache write lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let removed = before - entries.len();
        if removed > 0 {
            debug!(removed, remaining = entries.len(), "Cache cleanup complete");
        }
    }

    /// Returns the number of entries in the cache (including expired ones).
    pub fn len(&self) -> usize {
        match self.entries.read() {
            Ok(entries) => entries.len(),
            Err(poisoned) => {
                warn!("Cache read lock poisoned, recovering");
                poisoned.into_inner().len()
            }
        }
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        let mut entries = match self.entries.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Cache write lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        entries.clear();
    }
}

/// A single-value cache with TTL, useful for caching expensive one-off computations
/// like bootstrap data.
///
/// Provides stale-while-revalidate semantics: if refresh fails, stale data can be used.
pub struct SingleValueCache<V> {
    entry: RwLock<Option<CacheEntry<V>>>,
    ttl: Duration,
}

impl<V: Clone> SingleValueCache<V> {
    /// Creates a new single-value cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entry: RwLock::new(None),
            ttl,
        }
    }

    /// Gets the cached value if it exists and is not expired.
    pub fn get(&self) -> Option<V> {
        let guard = match self.entry.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("SingleValueCache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let entry = guard.as_ref()?;

        if entry.is_expired() {
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Gets the cached value even if expired (for fallback during refresh failures).
    pub fn get_stale(&self) -> Option<V> {
        let guard = match self.entry.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("SingleValueCache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        guard.as_ref().map(|e| e.value.clone())
    }

    /// Checks if the cache needs refresh (value is stale or missing).
    pub fn needs_refresh(&self) -> bool {
        let guard = match self.entry.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("SingleValueCache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };

        match guard.as_ref() {
            Some(e) => e.is_stale(),
            None => true,
        }
    }

    /// Checks if the cache has any value (even if expired).
    pub fn has_value(&self) -> bool {
        let guard = match self.entry.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("SingleValueCache read lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        guard.is_some()
    }

    /// Sets the cached value.
    pub fn set(&self, value: V) {
        let mut guard = match self.entry.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("SingleValueCache write lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        *guard = Some(CacheEntry::new(value, self.ttl));
    }

    /// Clears the cached value.
    pub fn clear(&self) {
        let mut guard = match self.entry.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("SingleValueCache write lock poisoned, recovering");
                poisoned.into_inner()
            }
        };
        *guard = None;
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
    fn test_cache_get_stale_after_expiration() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_millis(10));

        cache.insert("key".to_string(), "value".to_string());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // get() returns None for expired
        assert_eq!(cache.get(&"key".to_string()), None);
        // get_stale() still returns the value
        assert_eq!(
            cache.get_stale(&"key".to_string()),
            Some("value".to_string())
        );
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
    fn test_cache_cleanup() {
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_millis(10));

        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Add a fresh entry
        cache.insert_with_ttl("key3".to_string(), "value3".to_string(), Duration::from_secs(3600));

        assert_eq!(cache.len(), 3);

        cache.cleanup();

        // Only the fresh entry should remain
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"key3".to_string()), Some("value3".to_string()));
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

    #[test]
    fn test_single_value_cache() {
        let cache: SingleValueCache<String> = SingleValueCache::new(Duration::from_secs(3600));

        assert!(!cache.has_value());
        assert!(cache.get().is_none());

        cache.set("value".to_string());

        assert!(cache.has_value());
        assert_eq!(cache.get(), Some("value".to_string()));
    }

    #[test]
    fn test_single_value_cache_expiration() {
        let cache: SingleValueCache<String> = SingleValueCache::new(Duration::from_millis(10));

        cache.set("value".to_string());
        assert_eq!(cache.get(), Some("value".to_string()));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get().is_none());
        // Stale value still available
        assert_eq!(cache.get_stale(), Some("value".to_string()));
    }

    #[test]
    fn test_needs_refresh() {
        // TTL of 100ms, staleness at 75ms
        let cache: TtlCache<String, String> = TtlCache::new(Duration::from_millis(100));

        cache.insert("key".to_string(), "value".to_string());

        // Initially not stale
        assert!(!cache.needs_refresh(&"key".to_string()));

        // Wait until stale (75% of TTL)
        std::thread::sleep(Duration::from_millis(80));

        // Now should be stale
        assert!(cache.needs_refresh(&"key".to_string()));

        // But still valid (not expired)
        assert!(cache.get(&"key".to_string()).is_some());
    }
}
