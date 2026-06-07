use std::sync::atomic::{AtomicU64, Ordering};

/// NHP telemetry metrics.
pub struct NhpMetrics {
    pub knk_received: AtomicU64,
    pub knk_approved: AtomicU64,
    pub knk_rejected: AtomicU64,
    pub sessions_active: AtomicU64,
    pub sessions_established: AtomicU64,
    pub sessions_torn_down: AtomicU64,
    pub crypto_operations: AtomicU64,
    pub validation_errors: AtomicU64,
}

impl NhpMetrics {
    pub fn new() -> Self {
        Self {
            knk_received: AtomicU64::new(0),
            knk_approved: AtomicU64::new(0),
            knk_rejected: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            sessions_established: AtomicU64::new(0),
            sessions_torn_down: AtomicU64::new(0),
            crypto_operations: AtomicU64::new(0),
            validation_errors: AtomicU64::new(0),
        }
    }

    pub fn increment_knk_received(&self) { self.knk_received.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_knk_approved(&self) { self.knk_approved.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_knk_rejected(&self) { self.knk_rejected.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_sessions_active(&self) { self.sessions_active.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_sessions_established(&self) { self.sessions_established.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_sessions_torn_down(&self) { self.sessions_torn_down.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_crypto_operations(&self) { self.crypto_operations.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_validation_errors(&self) { self.validation_errors.fetch_add(1, Ordering::Relaxed); }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            knk_received: self.knk_received.load(Ordering::Relaxed),
            knk_approved: self.knk_approved.load(Ordering::Relaxed),
            knk_rejected: self.knk_rejected.load(Ordering::Relaxed),
            sessions_active: self.sessions_active.load(Ordering::Relaxed),
            sessions_established: self.sessions_established.load(Ordering::Relaxed),
            sessions_torn_down: self.sessions_torn_down.load(Ordering::Relaxed),
            crypto_operations: self.crypto_operations.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for NhpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub knk_received: u64,
    pub knk_approved: u64,
    pub knk_rejected: u64,
    pub sessions_active: u64,
    pub sessions_established: u64,
    pub sessions_torn_down: u64,
    pub crypto_operations: u64,
    pub validation_errors: u64,
}
