//! Canonical encoding system per specification §6.
//!
//! All data structures that participate in hashing, signing, or MAC computation
//! MUST use canonical encoding to ensure deterministic byte representation.
//!
//! # Encoding Rules
//!
//! - **Integers**: Little-endian encoding
//! - **Fixed Arrays**: Elements encoded consecutively without length prefix
//! - **Variable Sequences**: u32 length prefix followed by elements
//! - **Strings**: u32 byte length followed by UTF-8 bytes (no null terminator)
//! - **Options**: 0x00 for None, 0x01 + value for Some
//! - **Structs**: Fields encoded in declaration order without padding
//! - **Fieldless Enums**: u32 tag value (little-endian)
//! - **Payloaded Enums**: u32 tag followed by payload fields
//! - **Maps**: u32 count + key-value pairs sorted by encoded key bytes

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

/// Errors during canonical decoding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes to decode
    #[error("Insufficient bytes: expected {expected}, got {available}")]
    InsufficientBytes {
        /// Expected number of bytes
        expected: usize,
        /// Actually available bytes
        available: usize,
    },

    /// Invalid UTF-8 string
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(String),

    /// Invalid enum tag
    #[error("Invalid enum tag: {0}")]
    InvalidEnumTag(u32),

    /// Sequence too long
    #[error("Sequence too long: length {0} exceeds u32::MAX")]
    SequenceTooLong(usize),

    /// Duplicate map key
    #[error("Duplicate map key detected")]
    DuplicateMapKey,

    /// Map keys not sorted
    #[error("Map keys not sorted by encoded bytes")]
    UnsortedMapKeys,

    /// Custom decode error
    #[error("{0}")]
    Custom(String),
}

/// Trait for types that can be canonically encoded.
pub trait CanonicalEncode {
    /// Encodes the value to canonical byte representation.
    fn encode(&self, buf: &mut BytesMut);

    /// Returns the encoded byte representation.
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        buf.freeze()
    }

    /// Returns the encoded byte representation as a Vec.
    fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

/// Trait for types that can be decoded from canonical encoding.
pub trait CanonicalDecode: Sized {
    /// Decodes from canonical byte representation.
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError>;

    /// Decodes from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut buf = Bytes::copy_from_slice(bytes);
        Self::decode(&mut buf)
    }
}

// ============================================================================
// Primitive implementations
// ============================================================================

impl CanonicalEncode for u8 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self);
    }
}

impl CanonicalDecode for u8 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 1 {
            return Err(DecodeError::InsufficientBytes {
                expected: 1,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_u8())
    }
}

impl CanonicalEncode for i8 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i8(*self);
    }
}

impl CanonicalDecode for i8 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 1 {
            return Err(DecodeError::InsufficientBytes {
                expected: 1,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_i8())
    }
}

impl CanonicalEncode for u16 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16_le(*self);
    }
}

impl CanonicalDecode for u16 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::InsufficientBytes {
                expected: 2,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_u16_le())
    }
}

impl CanonicalEncode for i16 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i16_le(*self);
    }
}

impl CanonicalDecode for i16 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::InsufficientBytes {
                expected: 2,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_i16_le())
    }
}

impl CanonicalEncode for u32 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_le(*self);
    }
}

impl CanonicalDecode for u32 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 4 {
            return Err(DecodeError::InsufficientBytes {
                expected: 4,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_u32_le())
    }
}

impl CanonicalEncode for i32 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i32_le(*self);
    }
}

impl CanonicalDecode for i32 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 4 {
            return Err(DecodeError::InsufficientBytes {
                expected: 4,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_i32_le())
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64_le(*self);
    }
}

impl CanonicalDecode for u64 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 8 {
            return Err(DecodeError::InsufficientBytes {
                expected: 8,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_u64_le())
    }
}

impl CanonicalEncode for i64 {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i64_le(*self);
    }
}

impl CanonicalDecode for i64 {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 8 {
            return Err(DecodeError::InsufficientBytes {
                expected: 8,
                available: buf.remaining(),
            });
        }
        Ok(buf.get_i64_le())
    }
}

// ============================================================================
// Fixed array implementations
// ============================================================================

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(self);
    }
}

impl<const N: usize> CanonicalDecode for [u8; N] {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < N {
            return Err(DecodeError::InsufficientBytes {
                expected: N,
                available: buf.remaining(),
            });
        }
        let mut arr = [0u8; N];
        buf.copy_to_slice(&mut arr);
        Ok(arr)
    }
}

// ============================================================================
// Variable sequence implementations
// ============================================================================

impl<T: CanonicalEncode> CanonicalEncode for Vec<T> {
    fn encode(&self, buf: &mut BytesMut) {
        let len = self.len();
        assert!(
            len <= u32::MAX as usize,
            "Sequence length exceeds u32::MAX"
        );
        (len as u32).encode(buf);
        for item in self {
            item.encode(buf);
        }
    }
}

impl<T: CanonicalDecode> CanonicalDecode for Vec<T> {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let len = u32::decode(buf)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(buf)?);
        }
        Ok(vec)
    }
}

impl CanonicalEncode for &[u8] {
    fn encode(&self, buf: &mut BytesMut) {
        let len = self.len();
        assert!(
            len <= u32::MAX as usize,
            "Byte slice length exceeds u32::MAX"
        );
        (len as u32).encode(buf);
        buf.put_slice(self);
    }
}

// ============================================================================
// String implementation
// ============================================================================

impl CanonicalEncode for String {
    fn encode(&self, buf: &mut BytesMut) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        assert!(len <= u32::MAX as usize, "String length exceeds u32::MAX");
        (len as u32).encode(buf);
        buf.put_slice(bytes);
    }
}

impl CanonicalDecode for String {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let len = u32::decode(buf)? as usize;
        if buf.remaining() < len {
            return Err(DecodeError::InsufficientBytes {
                expected: len,
                available: buf.remaining(),
            });
        }
        let bytes = buf.copy_to_bytes(len);
        String::from_utf8(bytes.to_vec()).map_err(|e| DecodeError::InvalidUtf8(e.to_string()))
    }
}

impl CanonicalEncode for &str {
    fn encode(&self, buf: &mut BytesMut) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        assert!(len <= u32::MAX as usize, "String length exceeds u32::MAX");
        (len as u32).encode(buf);
        buf.put_slice(bytes);
    }
}

// ============================================================================
// Option implementation
// ============================================================================

impl<T: CanonicalEncode> CanonicalEncode for Option<T> {
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            None => buf.put_u8(0x00),
            Some(value) => {
                buf.put_u8(0x01);
                value.encode(buf);
            }
        }
    }
}

impl<T: CanonicalDecode> CanonicalDecode for Option<T> {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let tag = u8::decode(buf)?;
        match tag {
            0x00 => Ok(None),
            0x01 => Ok(Some(T::decode(buf)?)),
            _ => Err(DecodeError::InvalidEnumTag(tag as u32)),
        }
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Compares two values by their canonical encoding for deterministic ordering.
pub fn canonical_cmp<T: CanonicalEncode>(a: &T, b: &T) -> std::cmp::Ordering {
    a.to_bytes().cmp(&b.to_bytes())
}

/// Encodes a map as sorted key-value pairs.
///
/// Keys are sorted by their canonical byte representation.
/// Rejects duplicate keys (distinct keys producing identical encoded bytes).
pub fn encode_sorted_map<K: CanonicalEncode + Ord, V: CanonicalEncode>(
    map: &[(K, V)],
    buf: &mut BytesMut,
) -> Result<(), DecodeError> {
    let len = map.len();
    if len > u32::MAX as usize {
        return Err(DecodeError::SequenceTooLong(len));
    }

    // Sort by encoded key bytes
    let mut sorted: Vec<_> = map.iter().collect();
    sorted.sort_by(|a, b| canonical_cmp(&a.0, &b.0));

    // Check for duplicate encoded keys
    for i in 1..sorted.len() {
        if sorted[i - 1].0.to_bytes() == sorted[i].0.to_bytes() {
            return Err(DecodeError::DuplicateMapKey);
        }
    }

    (len as u32).encode(buf);
    for (key, value) in sorted {
        key.encode(buf);
        value.encode(buf);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_encoding() {
        // Test vector from §15.2: Timestamp(1700000000000)
        let timestamp: i64 = 1700000000000;
        let encoded = timestamp.to_bytes();
        let expected = hex::decode("0068e5cf8b010000").unwrap();
        assert_eq!(encoded.to_vec(), expected);
    }

    #[test]
    fn test_u32_encoding() {
        // CryptoVersion::V1 encodes as 01 00 00 00
        let value: u32 = 1;
        let encoded = value.to_bytes();
        assert_eq!(encoded.to_vec(), vec![0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_vec_encoding() {
        // Vec<u8> [0xAA, 0xBB, 0xCC] -> 03 00 00 00 AA BB CC
        let vec: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
        let encoded = vec.to_bytes();
        assert_eq!(
            encoded.to_vec(),
            vec![0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn test_option_none_encoding() {
        // Option::<u32>::None -> 00
        let opt: Option<u32> = None;
        let encoded = opt.to_bytes();
        assert_eq!(encoded.to_vec(), vec![0x00]);
    }

    #[test]
    fn test_option_some_encoding() {
        // Option::<u32>::Some(0x12345678) -> 01 78 56 34 12
        let opt: Option<u32> = Some(0x12345678);
        let encoded = opt.to_bytes();
        assert_eq!(encoded.to_vec(), vec![0x01, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_fixed_array_encoding() {
        let arr: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let encoded = arr.to_bytes();
        assert_eq!(encoded.to_vec(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_string_encoding() {
        let s = String::from("hello");
        let encoded = s.to_bytes();
        // Length (5) as u32 LE + "hello"
        assert_eq!(
            encoded.to_vec(),
            vec![0x05, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o']
        );
    }

    #[test]
    fn test_roundtrip_primitives() {
        // u8
        let val: u8 = 42;
        let decoded = u8::from_bytes(&val.to_vec()).unwrap();
        assert_eq!(val, decoded);

        // u32
        let val: u32 = 0x12345678;
        let decoded = u32::from_bytes(&val.to_vec()).unwrap();
        assert_eq!(val, decoded);

        // i64
        let val: i64 = -1234567890;
        let decoded = i64::from_bytes(&val.to_vec()).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_roundtrip_vec() {
        let vec: Vec<u32> = vec![1, 2, 3, 4, 5];
        let decoded = Vec::<u32>::from_bytes(&vec.to_vec()).unwrap();
        assert_eq!(vec, decoded);
    }

    #[test]
    fn test_roundtrip_option() {
        let opt_some: Option<u64> = Some(12345);
        let decoded = Option::<u64>::from_bytes(&opt_some.to_vec()).unwrap();
        assert_eq!(opt_some, decoded);

        let opt_none: Option<u64> = None;
        let decoded = Option::<u64>::from_bytes(&opt_none.to_vec()).unwrap();
        assert_eq!(opt_none, decoded);
    }

    #[test]
    fn test_canonical_cmp() {
        // Lower encoded bytes should come first
        let a: u32 = 100;
        let b: u32 = 200;
        assert_eq!(canonical_cmp(&a, &b), std::cmp::Ordering::Less);
    }
}
