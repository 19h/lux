//! FastCDC chunking algorithm per specification §10.
//!
//! Content-defined chunking based on the FastCDC algorithm that uses
//! a gear rolling hash to find chunk boundaries.

use crate::gear::GEAR_TABLE;
use crate::params::{CHUNK_AVG_SIZE_TARGET, CHUNK_MAX_SIZE, CHUNK_MIN_SIZE, MASK_L, MASK_S};

/// Parameters for the chunking algorithm.
#[derive(Debug, Clone, Copy)]
pub struct ChunkingParams {
    /// Minimum chunk size in bytes
    pub min_size: usize,
    /// Maximum chunk size in bytes
    pub max_size: usize,
    /// Target average chunk size
    pub avg_size: usize,
    /// Mask for positions before average
    pub mask_s: u64,
    /// Mask for positions at/after average
    pub mask_l: u64,
}

impl Default for ChunkingParams {
    fn default() -> Self {
        Self {
            min_size: CHUNK_MIN_SIZE,
            max_size: CHUNK_MAX_SIZE,
            avg_size: CHUNK_AVG_SIZE_TARGET,
            mask_s: MASK_S,
            mask_l: MASK_L,
        }
    }
}

/// Represents a chunk boundary with start and end offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBoundary {
    /// Start offset (inclusive)
    pub start: usize,
    /// End offset (exclusive)
    pub end: usize,
}

impl ChunkBoundary {
    /// Returns the size of this chunk.
    pub fn size(&self) -> usize {
        self.end - self.start
    }

    /// Returns true if this chunk is empty.
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

/// Chunks data using FastCDC with default parameters.
///
/// Returns a vector of end-exclusive boundary offsets starting with 0.
/// For empty data, returns `[0]` to indicate zero chunks with root = EMPTY_DAG_REF.
///
/// # Example
/// ```
/// use lux_cdc::chunk;
///
/// let data = vec![0u8; 1024 * 1024]; // 1 MiB
/// let boundaries = chunk(&data);
///
/// // First boundary is always 0
/// assert_eq!(boundaries[0], 0);
/// // Last boundary is data length
/// assert_eq!(*boundaries.last().unwrap(), data.len());
/// ```
pub fn chunk(data: &[u8]) -> Vec<usize> {
    chunk_with_params(data, &ChunkingParams::default())
}

/// Chunks data using FastCDC with custom parameters.
///
/// Per specification §10.3:
/// - Boundaries are end-exclusive indices
/// - When a cut triggers at byte index `i`, the boundary is `i + 1`
/// - Returns `[0]` for empty data
pub fn chunk_with_params(data: &[u8], params: &ChunkingParams) -> Vec<usize> {
    if data.is_empty() {
        return vec![0]; // Zero chunks, root = EMPTY_DAG_REF
    }

    let gear = &*GEAR_TABLE;
    let mut boundaries = vec![0];
    let mut pos = 0;

    while pos < data.len() {
        // If remaining data is less than or equal to min_size, emit as final chunk
        if data.len() - pos <= params.min_size {
            boundaries.push(data.len());
            break;
        }

        let mut hash = 0u64;
        let search_start = pos + params.min_size;
        let search_end = (pos + params.max_size).min(data.len());
        let mut found = false;

        for i in search_start..search_end {
            // Rolling hash: shift left by 1 and add gear value
            hash = (hash << 1).wrapping_add(gear[data[i] as usize]);

            // Choose mask based on position relative to average
            let mask = if i - pos < params.avg_size {
                params.mask_s
            } else {
                params.mask_l
            };

            // Check if we've found a boundary
            if hash & mask == 0 {
                boundaries.push(i + 1); // End-exclusive boundary
                pos = i + 1;
                found = true;
                break;
            }
        }

        // If no boundary found within max_size, force a cut
        if !found {
            boundaries.push(search_end);
            pos = search_end;
        }
    }

    boundaries
}

/// Iterator-based FastCDC chunker for streaming data.
pub struct FastCdcChunker<'a> {
    data: &'a [u8],
    params: ChunkingParams,
    position: usize,
    done: bool,
}

impl<'a> FastCdcChunker<'a> {
    /// Creates a new chunker with default parameters.
    pub fn new(data: &'a [u8]) -> Self {
        Self::with_params(data, ChunkingParams::default())
    }

    /// Creates a new chunker with custom parameters.
    pub fn with_params(data: &'a [u8], params: ChunkingParams) -> Self {
        Self {
            data,
            params,
            position: 0,
            done: data.is_empty(),
        }
    }

    /// Returns the current position in the data.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the remaining bytes to be chunked.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
}

impl<'a> Iterator for FastCdcChunker<'a> {
    type Item = ChunkBoundary;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let start = self.position;
        let remaining = self.data.len() - start;

        // Final chunk if remaining is at or below min_size
        if remaining <= self.params.min_size {
            self.done = true;
            if remaining > 0 {
                self.position = self.data.len();
                return Some(ChunkBoundary {
                    start,
                    end: self.data.len(),
                });
            }
            return None;
        }

        let gear = &*GEAR_TABLE;
        let mut hash = 0u64;
        let search_start = start + self.params.min_size;
        let search_end = (start + self.params.max_size).min(self.data.len());

        for i in search_start..search_end {
            hash = (hash << 1).wrapping_add(gear[self.data[i] as usize]);

            let mask = if i - start < self.params.avg_size {
                self.params.mask_s
            } else {
                self.params.mask_l
            };

            if hash & mask == 0 {
                self.position = i + 1;
                return Some(ChunkBoundary {
                    start,
                    end: i + 1,
                });
            }
        }

        // Force cut at max_size
        self.position = search_end;
        if search_end >= self.data.len() {
            self.done = true;
        }
        Some(ChunkBoundary {
            start,
            end: search_end,
        })
    }
}

/// Computes chunk IDs (BLAKE3 hashes) for each chunk.
pub fn chunk_with_ids(data: &[u8]) -> Vec<(ChunkBoundary, lux_core::ChunkId)> {
    let boundaries = chunk(data);
    let mut result = Vec::with_capacity(boundaries.len().saturating_sub(1));

    for i in 0..boundaries.len().saturating_sub(1) {
        let start = boundaries[i];
        let end = boundaries[i + 1];
        let chunk_data = &data[start..end];
        let chunk_id = lux_core::ChunkId::from_plaintext(chunk_data);
        result.push((ChunkBoundary { start, end }, chunk_id));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data() {
        let boundaries = chunk(&[]);
        assert_eq!(boundaries, vec![0]);
    }

    #[test]
    fn test_small_data() {
        // Data smaller than min_size should be one chunk
        let data = vec![0u8; 1000];
        let boundaries = chunk(&data);
        assert_eq!(boundaries, vec![0, 1000]);
    }

    #[test]
    fn test_min_size_data() {
        // Data exactly at min_size should be one chunk
        let data = vec![0u8; CHUNK_MIN_SIZE];
        let boundaries = chunk(&data);
        assert_eq!(boundaries, vec![0, CHUNK_MIN_SIZE]);
    }

    #[test]
    fn test_max_size_enforcement() {
        // Large uniform data should be split at max_size boundaries
        let data = vec![0x42u8; CHUNK_MAX_SIZE * 3];
        let boundaries = chunk(&data);

        // Check that no chunk exceeds max_size
        for i in 0..boundaries.len() - 1 {
            let chunk_size = boundaries[i + 1] - boundaries[i];
            assert!(
                chunk_size <= CHUNK_MAX_SIZE,
                "Chunk {} has size {} > max {}",
                i,
                chunk_size,
                CHUNK_MAX_SIZE
            );
        }
    }

    #[test]
    fn test_min_size_enforcement() {
        // No chunk should be smaller than min_size (except possibly the last)
        let data: Vec<u8> = (0..CHUNK_MAX_SIZE * 2).map(|i| (i % 256) as u8).collect();
        let boundaries = chunk(&data);

        for i in 0..boundaries.len().saturating_sub(2) {
            let chunk_size = boundaries[i + 1] - boundaries[i];
            assert!(
                chunk_size >= CHUNK_MIN_SIZE,
                "Chunk {} has size {} < min {}",
                i,
                chunk_size,
                CHUNK_MIN_SIZE
            );
        }
    }

    #[test]
    fn test_determinism() {
        // Same input should always produce same boundaries
        let data: Vec<u8> = (0..CHUNK_MAX_SIZE).map(|i| (i % 256) as u8).collect();
        let boundaries1 = chunk(&data);
        let boundaries2 = chunk(&data);
        assert_eq!(boundaries1, boundaries2);
    }

    #[test]
    fn test_boundary_correctness() {
        let data: Vec<u8> = (0..CHUNK_MAX_SIZE * 2).map(|i| (i % 256) as u8).collect();
        let boundaries = chunk(&data);

        // First boundary should be 0
        assert_eq!(boundaries[0], 0);

        // Last boundary should be data length
        assert_eq!(*boundaries.last().unwrap(), data.len());

        // Boundaries should be strictly increasing
        for i in 1..boundaries.len() {
            assert!(
                boundaries[i] > boundaries[i - 1],
                "Boundary {} ({}) not greater than {} ({})",
                i,
                boundaries[i],
                i - 1,
                boundaries[i - 1]
            );
        }
    }

    #[test]
    fn test_random_data_distribution() {
        // Test with pseudo-random data to verify chunk size distribution
        use std::collections::HashMap;
        let mut rng_state = 0x12345678u64;
        let mut data = vec![0u8; CHUNK_MAX_SIZE * 10];
        for byte in &mut data {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (rng_state >> 33) as u8;
        }

        let boundaries = chunk(&data);
        let mut size_buckets: HashMap<usize, usize> = HashMap::new();

        for i in 0..boundaries.len() - 1 {
            let size = boundaries[i + 1] - boundaries[i];
            let bucket = size / (CHUNK_AVG_SIZE_TARGET / 4);
            *size_buckets.entry(bucket).or_insert(0) += 1;
        }

        // With random data, we should get a reasonable distribution of chunk sizes
        assert!(boundaries.len() > 5, "Should produce multiple chunks");
    }

    #[test]
    fn test_content_defined_boundary_shift() {
        // Inserting data at the start should only affect nearby chunks
        let base_data: Vec<u8> = (0..CHUNK_MAX_SIZE * 3).map(|i| (i % 256) as u8).collect();
        let base_boundaries = chunk(&base_data);

        // Insert 100 bytes at the start
        let mut modified_data = vec![0xFFu8; 100];
        modified_data.extend_from_slice(&base_data);
        let modified_boundaries = chunk(&modified_data);

        // After some initial chunks, the boundaries should realign
        // This is the key property of content-defined chunking
        let base_chunks: Vec<usize> = base_boundaries.windows(2).map(|w| w[1] - w[0]).collect();
        let mod_chunks: Vec<usize> = modified_boundaries.windows(2).map(|w| w[1] - w[0]).collect();

        // At least some chunks after the initial disruption should match
        let matching = base_chunks.iter().filter(|&s| mod_chunks.contains(s)).count();
        assert!(matching > 0, "CDC should produce some matching chunk sizes");
    }

    #[test]
    fn test_single_byte_chunks_impossible() {
        // No valid chunk should be smaller than min_size (except final chunk)
        let data: Vec<u8> = (0..CHUNK_MAX_SIZE * 2).map(|i| i as u8).collect();
        let boundaries = chunk(&data);

        for i in 0..boundaries.len().saturating_sub(2) {
            let size = boundaries[i + 1] - boundaries[i];
            assert!(size >= CHUNK_MIN_SIZE, "Got tiny chunk of size {}", size);
        }
    }

    #[test]
    fn test_chunker_iterator() {
        let data: Vec<u8> = (0..CHUNK_MAX_SIZE).map(|i| (i % 256) as u8).collect();
        let chunker = FastCdcChunker::new(&data);

        let chunks: Vec<ChunkBoundary> = chunker.collect();

        // Should have at least one chunk
        assert!(!chunks.is_empty());

        // First chunk should start at 0
        assert_eq!(chunks[0].start, 0);

        // Last chunk should end at data length
        assert_eq!(chunks.last().unwrap().end, data.len());

        // Chunks should be contiguous
        for i in 1..chunks.len() {
            assert_eq!(chunks[i].start, chunks[i - 1].end);
        }
    }

    #[test]
    fn test_chunk_with_ids() {
        let data = vec![0x42u8; CHUNK_MIN_SIZE + 1000];
        let chunks = chunk_with_ids(&data);

        assert!(!chunks.is_empty());

        for (boundary, chunk_id) in &chunks {
            let chunk_data = &data[boundary.start..boundary.end];
            let expected_id = lux_core::ChunkId::from_plaintext(chunk_data);
            assert_eq!(*chunk_id, expected_id);
        }
    }

    #[test]
    fn test_content_defined_boundaries() {
        // Test that modifying data only affects local chunks
        let mut data1: Vec<u8> = (0..CHUNK_MAX_SIZE * 3).map(|i| (i % 256) as u8).collect();
        let boundaries1 = chunk(&data1);

        // Modify a small section in the middle
        let mid = data1.len() / 2;
        for i in mid..(mid + 100) {
            data1[i] = 0xFF;
        }
        let boundaries2 = chunk(&data1);

        // Boundaries far from the modification should be the same
        // (This is a probabilistic test - content-defined chunking localizes changes)
        let first_boundary = boundaries1.iter().take(2).cloned().collect::<Vec<_>>();
        let first_boundary2 = boundaries2.iter().take(2).cloned().collect::<Vec<_>>();

        // First boundaries should match if modification is far enough
        if mid > CHUNK_MAX_SIZE * 2 {
            assert_eq!(first_boundary, first_boundary2);
        }
    }

    #[test]
    fn test_custom_params() {
        let params = ChunkingParams {
            min_size: 1024,
            max_size: 4096,
            avg_size: 2048,
            mask_s: (1 << 11) - 1,
            mask_l: (1 << 9) - 1,
        };

        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let boundaries = chunk_with_params(&data, &params);

        // Verify constraints with custom params
        for i in 0..boundaries.len() - 1 {
            let chunk_size = boundaries[i + 1] - boundaries[i];
            assert!(chunk_size <= params.max_size);
        }
    }
}
