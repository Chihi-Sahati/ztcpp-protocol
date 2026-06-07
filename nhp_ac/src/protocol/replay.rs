use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Replay protection cache using a time-based sliding window.
///
/// Tracks recently seen nonces to detect replay attacks.
/// Nonces are automatically evicted after the expiry duration.
pub struct ReplayProtectionCache {
    seen: HashSet<String>,
    max_entries: usize,
    expiry: Duration,
    last_cleanup: Instant,
}

impl ReplayProtectionCache {
    /// Create a new replay protection cache.
    pub fn new(max_entries: usize, expiry_secs: u64) -> Self {
        Self {
            seen: HashSet::new(),
            max_entries,
            expiry: Duration::from_secs(expiry_secs),
            last_cleanup: Instant::now(),
        }
    }

    /// Check if a nonce has been seen before.
    /// If not, add it to the cache and return true (fresh).
    /// If already seen, return false (replay detected).
    pub fn check_and_add(&mut self, nonce: &str) -> bool {
        self.maybe_cleanup();
        if self.seen.contains(nonce) {
            false
        } else {
            if self.seen.len() >= self.max_entries {
                // Evict oldest entries by clearing
                self.seen.clear();
            }
            self.seen.insert(nonce.to_string());
            true
        }
    }

    /// Remove expired entries from the cache.
    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() > self.expiry {
            self.seen.clear();
            self.last_cleanup = Instant::now();
        }
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_nonce_accepted() {
        let mut cache = ReplayProtectionCache::new(1000, 300);
        assert!(cache.check_and_add("nonce-1"));
        assert!(cache.check_and_add("nonce-2"));
    }

    #[test]
    fn test_replayed_nonce_rejected() {
        let mut cache = ReplayProtectionCache::new(1000, 300);
        assert!(cache.check_and_add("nonce-1"));
        assert!(!cache.check_and_add("nonce-1")); // Replay!
    }

    #[test]
    fn test_different_nonces_accepted() {
        let mut cache = ReplayProtectionCache::new(1000, 300);
        for i in 0..100 {
            assert!(cache.check_and_add(&format!("nonce-{}", i)));
        }
    }
}
