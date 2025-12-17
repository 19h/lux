//! Lux CDC - Content-Defined Chunking implementation.
//!
//! Implements the FastCDC algorithm per specification §10 for partitioning
//! files into variable-size chunks based on content boundaries.
//!
//! # Design Rationale
//!
//! Fixed-size chunking causes insertion or deletion of data to shift all
//! subsequent chunk boundaries, invalidating downstream chunks for deduplication.
//! Content-defined boundaries localize changes: modifying one region affects
//! only adjacent chunks while preserving chunk identity elsewhere.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod fastcdc;
mod gear;

pub use fastcdc::{chunk, chunk_with_params, ChunkBoundary, ChunkingParams, FastCdcChunker};
pub use gear::{gear_table, GearTable, GEAR_TABLE};

/// Chunk size parameters per specification §10.1.
pub mod params {
    /// Minimum chunk size: 64 KiB
    pub const CHUNK_MIN_SIZE: usize = 65536;

    /// Maximum chunk size: 1 MiB
    pub const CHUNK_MAX_SIZE: usize = 1048576;

    /// Target average chunk size: 256 KiB (descriptive)
    pub const CHUNK_AVG_SIZE_TARGET: usize = 262144;

    /// Mask for positions before average (19 bits set)
    pub const MASK_S: u64 = (1 << 19) - 1;

    /// Mask for positions at/after average (17 bits set)
    pub const MASK_L: u64 = (1 << 17) - 1;
}
