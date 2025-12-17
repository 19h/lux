//! Gear table for FastCDC rolling hash.
//!
//! Per specification §10.2, the gear table is derived from BLAKE3 hashes
//! of single-byte inputs.

use std::sync::LazyLock;

/// Type alias for the gear table.
pub type GearTable = [u64; 256];

/// Pre-computed gear table (computed once at runtime).
pub static GEAR_TABLE: LazyLock<GearTable> = LazyLock::new(gear_table);

/// Generates the gear table per specification §10.2.
///
/// For each byte value 0-255, computes BLAKE3 of that single byte
/// and takes the first 8 bytes as a little-endian u64.
///
/// # Spot Checks (from specification)
/// - GEAR[0]   = 0xf1611bf1dfde3a2d
/// - GEAR[1]   = 0xe072c1bb1f72fc48
/// - GEAR[255] = 0x6d93c57b374dd499
pub fn gear_table() -> GearTable {
    let mut table = [0u64; 256];
    for i in 0..256 {
        let hash = blake3::hash(&[i as u8]);
        let bytes = hash.as_bytes();
        table[i] = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gear_table_spot_checks() {
        let table = gear_table();

        // Spot checks from specification §10.2
        assert_eq!(
            table[0],
            0xf1611bf1dfde3a2d,
            "GEAR[0] mismatch: got {:#x}",
            table[0]
        );
        assert_eq!(
            table[1],
            0xe072c1bb1f72fc48,
            "GEAR[1] mismatch: got {:#x}",
            table[1]
        );
        assert_eq!(
            table[255],
            0x6d93c57b374dd499,
            "GEAR[255] mismatch: got {:#x}",
            table[255]
        );
    }

    #[test]
    fn test_gear_table_derivation() {
        let table = gear_table();

        // Verify derivation from BLAKE3
        for i in 0..256 {
            let hash = blake3::hash(&[i as u8]);
            let bytes = hash.as_bytes();
            let expected = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            assert_eq!(table[i], expected, "GEAR[{}] derivation mismatch", i);
        }
    }

    #[test]
    fn test_gear_table_uniqueness() {
        let table = gear_table();

        // Verify all values are unique (extremely unlikely to have collisions)
        let mut values: Vec<u64> = table.to_vec();
        values.sort();
        for i in 1..values.len() {
            assert_ne!(
                values[i - 1],
                values[i],
                "Duplicate gear values found at position {}",
                i
            );
        }
    }

    #[test]
    fn test_lazy_static_table() {
        // Verify the lazy static table matches fresh computation
        let fresh = gear_table();
        for i in 0..256 {
            assert_eq!(GEAR_TABLE[i], fresh[i], "GEAR_TABLE[{}] mismatch", i);
        }
    }
}
