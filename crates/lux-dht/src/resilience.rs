//! Resilience Protocol implementation per specification §14.
//!
//! Manages data redundancy, health monitoring, and repair procedures
//! to ensure data availability in the face of node churn.

use std::collections::HashMap;
use std::time::Duration;

use lux_core::{CiphertextHash, NodeId, Timestamp};
use lux_proto::dht::{ChunkAnnouncement, ChunkHolders, StorageLeaseBody};
use parking_lot::RwLock;

/// Default minimum replicas per specification §16.1.
pub const DEFAULT_MIN_REPLICAS: u8 = 3;

/// Default lease TTL in days per specification §16.1.
pub const DEFAULT_LEASE_TTL_DAYS: u64 = 7;

/// Default repair check interval in hours per specification §16.1.
pub const DEFAULT_REPAIR_CHECK_INTERVAL_HOURS: u64 = 1;

/// Resilience policy for an object per specification §14.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResiliencePolicy {
    /// Minimum concurrent holders required.
    pub min_replicas: u8,
    /// Lease duration before renewal.
    pub lease_ttl: Duration,
    /// Trigger repair when replicas fall below this threshold.
    pub repair_threshold: u8,
}

impl Default for ResiliencePolicy {
    fn default() -> Self {
        Self {
            min_replicas: DEFAULT_MIN_REPLICAS,
            lease_ttl: Duration::from_secs(DEFAULT_LEASE_TTL_DAYS * 24 * 3600),
            repair_threshold: DEFAULT_MIN_REPLICAS,
        }
    }
}

impl ResiliencePolicy {
    /// Creates a new resilience policy.
    pub fn new(min_replicas: u8, lease_ttl_days: u64, repair_threshold: u8) -> Self {
        Self {
            min_replicas,
            lease_ttl: Duration::from_secs(lease_ttl_days * 24 * 3600),
            repair_threshold,
        }
    }

    /// Creates a policy for highly resilient data (5 replicas).
    pub fn high_resilience() -> Self {
        Self {
            min_replicas: 5,
            lease_ttl: Duration::from_secs(14 * 24 * 3600), // 14 days
            repair_threshold: 4,
        }
    }

    /// Creates a policy for temporary/cache data (2 replicas).
    pub fn low_resilience() -> Self {
        Self {
            min_replicas: 2,
            lease_ttl: Duration::from_secs(24 * 3600), // 1 day
            repair_threshold: 1,
        }
    }
}

/// Health status for a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkHealth {
    /// Chunk has sufficient replicas.
    Healthy,
    /// Chunk is below repair threshold but above 0.
    AtRisk {
        /// Current number of holders
        current: u8,
        /// Repair threshold below which repair is needed
        threshold: u8,
    },
    /// Chunk has no known holders.
    Lost,
}

/// Information about a chunk that needs repair.
#[derive(Debug, Clone)]
pub struct RepairTask {
    /// The chunk to repair.
    pub ciphertext_hash: CiphertextHash,
    /// Current number of holders.
    pub current_holders: u8,
    /// Target number of holders.
    pub target_holders: u8,
    /// Existing holder nodes (to avoid).
    pub existing_holders: Vec<NodeId>,
}

/// Result of a health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Chunks that are healthy.
    pub healthy: Vec<CiphertextHash>,
    /// Chunks at risk (below threshold but not lost).
    pub at_risk: Vec<RepairTask>,
    /// Chunks with no known holders.
    pub lost: Vec<CiphertextHash>,
    /// Total chunks checked.
    pub total_checked: usize,
}

impl HealthCheckResult {
    /// Returns true if all chunks are healthy.
    pub fn is_all_healthy(&self) -> bool {
        self.at_risk.is_empty() && self.lost.is_empty()
    }

    /// Returns the number of chunks needing repair.
    pub fn needs_repair_count(&self) -> usize {
        self.at_risk.len() + self.lost.len()
    }
}

/// Resilience manager for monitoring and repairing chunk redundancy.
pub struct ResilienceManager {
    /// Default policy for new objects.
    default_policy: ResiliencePolicy,
    /// Per-chunk policies (overrides default).
    chunk_policies: RwLock<HashMap<CiphertextHash, ResiliencePolicy>>,
    /// Last health check results.
    last_check: RwLock<Option<(Timestamp, HealthCheckResult)>>,
    /// Repair check interval.
    check_interval: Duration,
}

impl ResilienceManager {
    /// Creates a new resilience manager with default settings.
    pub fn new() -> Self {
        Self {
            default_policy: ResiliencePolicy::default(),
            chunk_policies: RwLock::new(HashMap::new()),
            last_check: RwLock::new(None),
            check_interval: Duration::from_secs(DEFAULT_REPAIR_CHECK_INTERVAL_HOURS * 3600),
        }
    }

    /// Creates a new resilience manager with custom default policy.
    pub fn with_policy(policy: ResiliencePolicy) -> Self {
        Self {
            default_policy: policy,
            chunk_policies: RwLock::new(HashMap::new()),
            last_check: RwLock::new(None),
            check_interval: Duration::from_secs(DEFAULT_REPAIR_CHECK_INTERVAL_HOURS * 3600),
        }
    }

    /// Sets the policy for a specific chunk.
    pub fn set_chunk_policy(&self, hash: CiphertextHash, policy: ResiliencePolicy) {
        self.chunk_policies.write().insert(hash, policy);
    }

    /// Gets the policy for a chunk (default if not overridden).
    pub fn get_policy(&self, hash: &CiphertextHash) -> ResiliencePolicy {
        self.chunk_policies
            .read()
            .get(hash)
            .copied()
            .unwrap_or(self.default_policy)
    }

    /// Checks the health of a single chunk per specification §14.2.
    ///
    /// 1. Query DHT for ChunkHolders records
    /// 2. Count distinct, non-expired holders
    /// 3. Compare against repair threshold
    pub fn check_chunk_health(
        &self,
        hash: &CiphertextHash,
        holders: &ChunkHolders,
    ) -> ChunkHealth {
        let policy = self.get_policy(hash);
        let now = Timestamp::now();

        // Count non-expired holders
        let valid_holders: Vec<_> = holders
            .holders
            .iter()
            .filter(|(_, ann)| ann.lease.body.expires_at.is_after(&now))
            .collect();

        let count = valid_holders.len() as u8;

        if count >= policy.repair_threshold {
            ChunkHealth::Healthy
        } else if count > 0 {
            ChunkHealth::AtRisk {
                current: count,
                threshold: policy.repair_threshold,
            }
        } else {
            ChunkHealth::Lost
        }
    }

    /// Performs a health check on multiple chunks per specification §14.2.
    pub fn check_health(
        &self,
        chunks: &[(CiphertextHash, ChunkHolders)],
    ) -> HealthCheckResult {
        let now = Timestamp::now();
        let mut healthy = Vec::new();
        let mut at_risk = Vec::new();
        let mut lost = Vec::new();

        for (hash, holders) in chunks {
            let policy = self.get_policy(hash);

            // Count non-expired holders
            let valid_holders: Vec<&NodeId> = holders
                .holders
                .iter()
                .filter(|(_, ann)| ann.lease.body.expires_at.is_after(&now))
                .map(|(id, _)| id)
                .collect();

            let count = valid_holders.len() as u8;

            if count >= policy.repair_threshold {
                healthy.push(*hash);
            } else if count > 0 {
                at_risk.push(RepairTask {
                    ciphertext_hash: *hash,
                    current_holders: count,
                    target_holders: policy.min_replicas,
                    existing_holders: valid_holders.into_iter().copied().collect(),
                });
            } else {
                lost.push(*hash);
            }
        }

        let result = HealthCheckResult {
            total_checked: chunks.len(),
            healthy,
            at_risk,
            lost,
        };

        // Store the result
        *self.last_check.write() = Some((now, result.clone()));

        result
    }

    /// Creates a repair plan for under-replicated chunks per specification §14.3.
    ///
    /// For each chunk:
    /// 1. Identify under-replicated chunks
    /// 2. Calculate how many new replicas needed
    /// 3. Return list of repair tasks
    pub fn create_repair_plan(&self, health: &HealthCheckResult) -> Vec<RepairTask> {
        health.at_risk.clone()
    }

    /// Checks if a lease needs renewal per specification §14.4.
    pub fn needs_renewal(&self, lease: &StorageLeaseBody) -> bool {
        let remaining = lease.time_remaining();
        let policy = self.get_policy(&lease.locator.ciphertext_hash);

        // Renew when less than 1/4 of TTL remains
        let renewal_threshold = policy.lease_ttl / 4;

        match remaining {
            Some(duration) => duration < renewal_threshold,
            None => true, // Already expired
        }
    }

    /// Calculates when a lease should be renewed.
    pub fn renewal_time(&self, lease: &StorageLeaseBody) -> Timestamp {
        let policy = self.get_policy(&lease.locator.ciphertext_hash);
        let renewal_threshold = policy.lease_ttl / 4;

        // Renew at 3/4 of the way through the lease
        let renewal_offset = policy.lease_ttl - renewal_threshold;

        Timestamp::new(lease.issued_at.0 + renewal_offset.as_millis() as i64)
    }

    /// Returns the last health check result if available.
    pub fn last_health_check(&self) -> Option<(Timestamp, HealthCheckResult)> {
        self.last_check.read().clone()
    }

    /// Returns true if it's time for another health check.
    pub fn should_check(&self) -> bool {
        match &*self.last_check.read() {
            None => true,
            Some((timestamp, _)) => {
                let elapsed = Timestamp::now()
                    .duration_since(timestamp)
                    .unwrap_or(Duration::ZERO);
                elapsed >= self.check_interval
            }
        }
    }
}

impl Default for ResilienceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about resilience operations.
#[derive(Debug, Clone, Default)]
pub struct ResilienceStats {
    /// Total health checks performed.
    pub health_checks: u64,
    /// Total repairs initiated.
    pub repairs_initiated: u64,
    /// Total repairs completed.
    pub repairs_completed: u64,
    /// Total repairs failed.
    pub repairs_failed: u64,
    /// Total leases renewed.
    pub leases_renewed: u64,
    /// Chunks currently at risk.
    pub chunks_at_risk: u64,
    /// Chunks currently lost.
    pub chunks_lost: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lux_core::ChunkId;
    use lux_proto::dag::CiphertextCommitment;
    use lux_proto::dht::{ChunkLocator, StorageLease};

    fn create_test_lease(holder: NodeId, expires_at: Timestamp) -> StorageLease {
        StorageLease {
            body: StorageLeaseBody {
                locator: ChunkLocator {
                    chunk_id: ChunkId::new([0xAA; 32]),
                    ciphertext_hash: CiphertextHash::new([0xBB; 32]),
                },
                commitment: CiphertextCommitment {
                    merkle_root: [0; 32],
                    size: 1000,
                    block_size: 1000,
                    block_count: 1,
                },
                holder,
                issuer: NodeId::new([0xFF; 32]),
                issued_at: Timestamp::new(0),
                expires_at,
            },
            issuer_signature: [0; 64],
            holder_signature: [0; 64],
        }
    }

    #[test]
    fn test_resilience_policy_default() {
        let policy = ResiliencePolicy::default();
        assert_eq!(policy.min_replicas, DEFAULT_MIN_REPLICAS);
        assert_eq!(policy.repair_threshold, DEFAULT_MIN_REPLICAS);
    }

    #[test]
    fn test_chunk_health_healthy() {
        let manager = ResilienceManager::new();
        let hash = CiphertextHash::new([0xBB; 32]);
        let mut holders = ChunkHolders::new();

        // Add 3 non-expired holders
        let future = Timestamp::new(Timestamp::now().0 + 3600000);
        for i in 0..3 {
            let mut holder_bytes = [0u8; 32];
            holder_bytes[0] = i;
            let lease = create_test_lease(NodeId::new(holder_bytes), future);
            holders.add(ChunkAnnouncement { lease });
        }

        assert_eq!(manager.check_chunk_health(&hash, &holders), ChunkHealth::Healthy);
    }

    #[test]
    fn test_chunk_health_at_risk() {
        let manager = ResilienceManager::new();
        let hash = CiphertextHash::new([0xBB; 32]);
        let mut holders = ChunkHolders::new();

        // Add only 1 non-expired holder (below threshold of 3)
        let future = Timestamp::new(Timestamp::now().0 + 3600000);
        let lease = create_test_lease(NodeId::new([0x01; 32]), future);
        holders.add(ChunkAnnouncement { lease });

        match manager.check_chunk_health(&hash, &holders) {
            ChunkHealth::AtRisk { current, threshold } => {
                assert_eq!(current, 1);
                assert_eq!(threshold, DEFAULT_MIN_REPLICAS);
            }
            other => panic!("Expected AtRisk, got {:?}", other),
        }
    }

    #[test]
    fn test_chunk_health_lost() {
        let manager = ResilienceManager::new();
        let hash = CiphertextHash::new([0xBB; 32]);
        let holders = ChunkHolders::new();

        assert_eq!(manager.check_chunk_health(&hash, &holders), ChunkHealth::Lost);
    }

    #[test]
    fn test_chunk_health_expired_not_counted() {
        let manager = ResilienceManager::new();
        let hash = CiphertextHash::new([0xBB; 32]);
        let mut holders = ChunkHolders::new();

        // Add 3 expired holders
        let past = Timestamp::new(Timestamp::now().0 - 3600000);
        for i in 0..3 {
            let mut holder_bytes = [0u8; 32];
            holder_bytes[0] = i;
            let lease = create_test_lease(NodeId::new(holder_bytes), past);
            holders.add(ChunkAnnouncement { lease });
        }

        // All expired, so chunk is lost
        assert_eq!(manager.check_chunk_health(&hash, &holders), ChunkHealth::Lost);
    }

    #[test]
    fn test_health_check_result() {
        let manager = ResilienceManager::new();
        let future = Timestamp::new(Timestamp::now().0 + 3600000);

        // Create healthy chunk (3 holders)
        let hash1 = CiphertextHash::new([0x01; 32]);
        let mut holders1 = ChunkHolders::new();
        for i in 0..3 {
            let mut holder_bytes = [0u8; 32];
            holder_bytes[0] = i;
            let mut lease = create_test_lease(NodeId::new(holder_bytes), future);
            lease.body.locator.ciphertext_hash = hash1;
            holders1.add(ChunkAnnouncement { lease });
        }

        // Create at-risk chunk (1 holder)
        let hash2 = CiphertextHash::new([0x02; 32]);
        let mut holders2 = ChunkHolders::new();
        let mut lease = create_test_lease(NodeId::new([0x10; 32]), future);
        lease.body.locator.ciphertext_hash = hash2;
        holders2.add(ChunkAnnouncement { lease });

        // Create lost chunk (0 holders)
        let hash3 = CiphertextHash::new([0x03; 32]);
        let holders3 = ChunkHolders::new();

        let chunks = vec![
            (hash1, holders1),
            (hash2, holders2),
            (hash3, holders3),
        ];

        let result = manager.check_health(&chunks);

        assert_eq!(result.total_checked, 3);
        assert_eq!(result.healthy.len(), 1);
        assert_eq!(result.at_risk.len(), 1);
        assert_eq!(result.lost.len(), 1);
        assert!(!result.is_all_healthy());
        assert_eq!(result.needs_repair_count(), 2);
    }

    #[test]
    fn test_custom_policy() {
        let manager = ResilienceManager::new();
        let hash = CiphertextHash::new([0xBB; 32]);

        // Set custom high-resilience policy
        manager.set_chunk_policy(hash, ResiliencePolicy::high_resilience());

        let policy = manager.get_policy(&hash);
        assert_eq!(policy.min_replicas, 5);

        // Other chunks still use default
        let other_hash = CiphertextHash::new([0xCC; 32]);
        let other_policy = manager.get_policy(&other_hash);
        assert_eq!(other_policy.min_replicas, DEFAULT_MIN_REPLICAS);
    }

    #[test]
    fn test_needs_renewal() {
        let manager = ResilienceManager::new();

        // Lease that expires in 1 day (should renew, as < 1/4 of 7-day TTL)
        let one_day_from_now = Timestamp::new(Timestamp::now().0 + 86400000);
        let lease1 = create_test_lease(NodeId::new([0x01; 32]), one_day_from_now);
        assert!(manager.needs_renewal(&lease1.body));

        // Lease that expires in 6 days (should not renew yet)
        let six_days_from_now = Timestamp::new(Timestamp::now().0 + 6 * 86400000);
        let lease2 = create_test_lease(NodeId::new([0x02; 32]), six_days_from_now);
        assert!(!manager.needs_renewal(&lease2.body));
    }
}
