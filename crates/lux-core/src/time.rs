//! Timestamp and clock skew handling per specification §7.1 and §16.
//!
//! Defines the Timestamp type (milliseconds since Unix epoch) and
//! clock skew validation logic.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
use crate::MAX_CLOCK_SKEW_MS;

/// Timestamp in milliseconds since Unix epoch.
///
/// Used throughout Lux for:
/// - Manifest creation and modification times
/// - Lease issuance and expiration
/// - DHT record timestamps
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// Creates a new timestamp from milliseconds since Unix epoch.
    pub const fn new(millis: i64) -> Self {
        Self(millis)
    }

    /// Returns the current time as a timestamp.
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch");
        Self(duration.as_millis() as i64)
    }

    /// Returns the milliseconds since Unix epoch.
    pub const fn as_millis(&self) -> i64 {
        self.0
    }

    /// Returns the seconds since Unix epoch (truncated).
    pub const fn as_secs(&self) -> i64 {
        self.0 / 1000
    }

    /// Creates from a SystemTime.
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        time.duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| Self(d.as_millis() as i64))
    }

    /// Converts to a SystemTime.
    pub fn to_system_time(&self) -> Option<SystemTime> {
        if self.0 >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_millis(self.0 as u64))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_millis((-self.0) as u64))
        }
    }

    /// Returns true if this timestamp is within acceptable clock skew of the reference.
    ///
    /// Per specification §16.1, MAX_CLOCK_SKEW is 300,000ms (5 minutes).
    pub fn within_clock_skew(&self, reference: &Timestamp) -> bool {
        let diff = (self.0 - reference.0).abs();
        diff <= MAX_CLOCK_SKEW_MS
    }

    /// Returns true if this timestamp is within acceptable clock skew of now.
    pub fn is_valid(&self) -> bool {
        self.within_clock_skew(&Timestamp::now())
    }

    /// Returns true if this timestamp is in the past relative to the reference.
    pub fn is_before(&self, other: &Timestamp) -> bool {
        self.0 < other.0
    }

    /// Returns true if this timestamp is in the future relative to the reference.
    pub fn is_after(&self, other: &Timestamp) -> bool {
        self.0 > other.0
    }

    /// Adds a duration to this timestamp.
    pub fn add(&self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration.as_millis() as i64))
    }

    /// Subtracts a duration from this timestamp.
    pub fn sub(&self, duration: Duration) -> Self {
        Self(self.0.saturating_sub(duration.as_millis() as i64))
    }

    /// Returns the duration between two timestamps.
    pub fn duration_since(&self, earlier: &Timestamp) -> Option<Duration> {
        if self.0 >= earlier.0 {
            Some(Duration::from_millis((self.0 - earlier.0) as u64))
        } else {
            None
        }
    }
}

impl CanonicalEncode for Timestamp {
    fn encode(&self, buf: &mut BytesMut) {
        self.0.encode(buf);
    }
}

impl CanonicalDecode for Timestamp {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self(i64::decode(buf)?))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(time) = self.to_system_time() {
            // Format as ISO 8601-ish for readability
            write!(f, "{:?}", time)
        } else {
            write!(f, "{}ms", self.0)
        }
    }
}

impl From<i64> for Timestamp {
    fn from(millis: i64) -> Self {
        Self(millis)
    }
}

impl From<Timestamp> for i64 {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

/// Time-to-live duration for storage leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseTtl(Duration);

impl LeaseTtl {
    /// Default lease TTL of 7 days per specification §16.1.
    pub const DEFAULT_DAYS: u64 = 7;

    /// Creates a new lease TTL.
    pub const fn new(duration: Duration) -> Self {
        Self(duration)
    }

    /// Creates a lease TTL from days.
    pub const fn from_days(days: u64) -> Self {
        Self(Duration::from_secs(days * 24 * 60 * 60))
    }

    /// Creates a lease TTL from hours.
    pub const fn from_hours(hours: u64) -> Self {
        Self(Duration::from_secs(hours * 60 * 60))
    }

    /// Returns the default lease TTL (7 days).
    pub const fn default_ttl() -> Self {
        Self::from_days(Self::DEFAULT_DAYS)
    }

    /// Returns the inner duration.
    pub const fn as_duration(&self) -> Duration {
        self.0
    }

    /// Calculates the expiration timestamp from an issue time.
    pub fn expires_at(&self, issued_at: Timestamp) -> Timestamp {
        issued_at.add(self.0)
    }
}

impl Default for LeaseTtl {
    fn default() -> Self {
        Self::default_ttl()
    }
}

/// Clock skew validator for DHT record timestamps.
pub struct ClockSkewValidator {
    max_skew_ms: i64,
}

impl ClockSkewValidator {
    /// Creates a new validator with the default max skew.
    pub fn new() -> Self {
        Self {
            max_skew_ms: MAX_CLOCK_SKEW_MS,
        }
    }

    /// Creates a new validator with a custom max skew.
    pub fn with_max_skew(max_skew_ms: i64) -> Self {
        Self { max_skew_ms }
    }

    /// Validates that a timestamp is within acceptable skew of now.
    pub fn validate(&self, timestamp: &Timestamp) -> Result<(), ClockSkewError> {
        let now = Timestamp::now();
        let diff = (timestamp.0 - now.0).abs();

        if diff > self.max_skew_ms {
            Err(ClockSkewError {
                timestamp: *timestamp,
                reference: now,
                skew_ms: diff,
                max_skew_ms: self.max_skew_ms,
            })
        } else {
            Ok(())
        }
    }
}

impl Default for ClockSkewValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Error when timestamp exceeds acceptable clock skew.
#[derive(Debug, Clone)]
pub struct ClockSkewError {
    /// The timestamp that was validated.
    pub timestamp: Timestamp,
    /// The reference timestamp (usually now).
    pub reference: Timestamp,
    /// The actual skew in milliseconds.
    pub skew_ms: i64,
    /// The maximum allowed skew.
    pub max_skew_ms: i64,
}

impl fmt::Display for ClockSkewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Clock skew exceeded: {}ms (max {}ms)",
            self.skew_ms, self.max_skew_ms
        )
    }
}

impl std::error::Error for ClockSkewError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_encoding() {
        // Test vector from §15.2: Timestamp(1700000000000)
        let ts = Timestamp::new(1700000000000);
        let encoded = ts.to_bytes();
        let expected = hex::decode("0068e5cf8b010000").unwrap();
        assert_eq!(encoded.to_vec(), expected);
    }

    #[test]
    fn test_timestamp_roundtrip() {
        let original = Timestamp::now();
        let encoded = original.to_bytes();
        let decoded = Timestamp::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_timestamp_now() {
        let ts = Timestamp::now();
        // Should be after 2024-01-01
        assert!(ts.0 > 1704067200000);
    }

    #[test]
    fn test_clock_skew_validation() {
        let now = Timestamp::now();

        // Within skew
        let valid = Timestamp::new(now.0 + 60_000); // 1 minute ahead
        assert!(valid.within_clock_skew(&now));

        // Beyond skew
        let invalid = Timestamp::new(now.0 + 400_000); // 6.67 minutes ahead
        assert!(!invalid.within_clock_skew(&now));
    }

    #[test]
    fn test_lease_ttl() {
        let issued = Timestamp::new(1700000000000);
        let ttl = LeaseTtl::from_days(7);
        let expires = ttl.expires_at(issued);

        // 7 days = 604800000ms
        assert_eq!(expires.0, 1700000000000 + 604800000);
    }

    #[test]
    fn test_timestamp_arithmetic() {
        let ts = Timestamp::new(1000000);
        let duration = Duration::from_millis(5000);

        let added = ts.add(duration);
        assert_eq!(added.0, 1005000);

        let subtracted = ts.sub(duration);
        assert_eq!(subtracted.0, 995000);
    }

    #[test]
    fn test_duration_since() {
        let earlier = Timestamp::new(1000000);
        let later = Timestamp::new(1005000);

        let duration = later.duration_since(&earlier).unwrap();
        assert_eq!(duration.as_millis(), 5000);

        // Earlier from later should be None
        assert!(earlier.duration_since(&later).is_none());
    }

    #[test]
    fn test_clock_skew_validator() {
        let validator = ClockSkewValidator::with_max_skew(1000); // 1 second
        let now = Timestamp::now();

        // Within skew
        let valid = Timestamp::new(now.0 + 500);
        assert!(validator.validate(&valid).is_ok());

        // Beyond skew
        let invalid = Timestamp::new(now.0 + 2000);
        assert!(validator.validate(&invalid).is_err());
    }
}
