//! Single-use nonce store for challenge-response attestation.
//!
//! Each nonce is a 32-byte random hex string, valid for one use within
//! a configurable TTL window.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::RngCore;

/// Maximum number of outstanding nonces to prevent unbounded memory growth.
const MAX_NONCES: usize = 100_000;

pub struct NonceStore {
    store: HashMap<String, Instant>,
    ttl: Duration,
}

impl NonceStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            store: HashMap::new(),
            ttl,
        }
    }

    /// Issue a fresh 32-byte hex nonce.
    pub fn issue(&mut self) -> String {
        // Sweep expired nonces first
        self.sweep();

        // Check capacity and evict oldest if still at limit
        if self.store.len() >= MAX_NONCES {
            tracing::warn!(
                capacity = MAX_NONCES,
                current = self.store.len(),
                "nonce store at capacity, evicting oldest entries"
            );
            let mut entries: Vec<_> = self.store.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by_key(|(_, v)| *v);
            let to_remove = entries.len() / 4; // Remove oldest 25%
            for (k, _) in entries.into_iter().take(to_remove) {
                self.store.remove(&k);
            }
        }

        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let nonce = hex::encode(bytes);
        self.store.insert(nonce.clone(), Instant::now());
        nonce
    }

    /// Consume a nonce — returns true if valid and not expired.
    pub fn consume(&mut self, nonce: &str) -> bool {
        match self.store.remove(nonce) {
            Some(created_at) => created_at.elapsed() < self.ttl,
            None => false,
        }
    }

    /// Remove expired nonces.
    fn sweep(&mut self) {
        let ttl = self.ttl;
        self.store
            .retain(|_, created_at| created_at.elapsed() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_issue_and_consume() {
        let mut store = NonceStore::new(Duration::from_secs(60));
        let nonce = store.issue();
        assert!(store.consume(&nonce));
        // Second consume should fail (single-use)
        assert!(!store.consume(&nonce));
    }

    #[test]
    fn test_invalid_nonce() {
        let mut store = NonceStore::new(Duration::from_secs(60));
        assert!(!store.consume("invalid_nonce"));
    }
}
