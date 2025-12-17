//! Network message types and framing.
//!
//! Defines the message types exchanged between nodes over the network.

use bytes::{Bytes, BytesMut};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
use lux_core::{ChunkId, CiphertextHash, NodeId, ObjectId, RevisionId};
use serde::{Deserialize, Serialize};

use crate::dht::{ChunkHolders, DhtRecord, ManifestAnnouncement, NodeAnnouncement};
use crate::storage::StoredChunk;

/// Message type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageType {
    // DHT operations
    /// Ping request
    Ping = 0,
    /// Pong response
    Pong = 1,
    /// Find node request
    FindNode = 2,
    /// Find node response
    FindNodeResponse = 3,
    /// Store record request
    StoreRecord = 4,
    /// Store record response
    StoreRecordResponse = 5,
    /// Find value request
    FindValue = 6,
    /// Find value response
    FindValueResponse = 7,

    // Chunk operations
    /// Get chunk request
    GetChunk = 10,
    /// Get chunk response
    GetChunkResponse = 11,
    /// Store chunk request
    StoreChunk = 12,
    /// Store chunk response
    StoreChunkResponse = 13,

    // Manifest operations
    /// Get manifest request
    GetManifest = 20,
    /// Get manifest response
    GetManifestResponse = 21,
    /// Publish manifest request
    PublishManifest = 22,
    /// Publish manifest response
    PublishManifestResponse = 23,

    // Error response
    /// Error message
    Error = 255,
}

impl MessageType {
    /// Returns the tag value.
    pub fn tag(&self) -> u32 {
        *self as u32
    }

    /// Creates from a tag value.
    pub fn from_tag(tag: u32) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(MessageType::Ping),
            1 => Ok(MessageType::Pong),
            2 => Ok(MessageType::FindNode),
            3 => Ok(MessageType::FindNodeResponse),
            4 => Ok(MessageType::StoreRecord),
            5 => Ok(MessageType::StoreRecordResponse),
            6 => Ok(MessageType::FindValue),
            7 => Ok(MessageType::FindValueResponse),
            10 => Ok(MessageType::GetChunk),
            11 => Ok(MessageType::GetChunkResponse),
            12 => Ok(MessageType::StoreChunk),
            13 => Ok(MessageType::StoreChunkResponse),
            20 => Ok(MessageType::GetManifest),
            21 => Ok(MessageType::GetManifestResponse),
            22 => Ok(MessageType::PublishManifest),
            23 => Ok(MessageType::PublishManifestResponse),
            255 => Ok(MessageType::Error),
            _ => Err(DecodeError::InvalidEnumTag(tag)),
        }
    }
}

/// Request/response ID for matching.
pub type RequestId = u64;

/// Error codes for error responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ErrorCode {
    /// Unknown error
    Unknown = 0,
    /// Record not found
    NotFound = 1,
    /// Invalid request
    InvalidRequest = 2,
    /// Authentication failed
    AuthFailed = 3,
    /// Timeout
    Timeout = 4,
    /// Storage full
    StorageFull = 5,
    /// Rate limited
    RateLimited = 6,
}

impl ErrorCode {
    /// Creates from a tag value.
    pub fn from_tag(tag: u32) -> Self {
        match tag {
            1 => ErrorCode::NotFound,
            2 => ErrorCode::InvalidRequest,
            3 => ErrorCode::AuthFailed,
            4 => ErrorCode::Timeout,
            5 => ErrorCode::StorageFull,
            6 => ErrorCode::RateLimited,
            _ => ErrorCode::Unknown,
        }
    }
}

/// Network message envelope.
#[derive(Debug, Clone)]
pub struct Message {
    /// Unique request identifier
    pub request_id: RequestId,
    /// Sender node ID
    pub sender: NodeId,
    /// Message payload
    pub payload: MessagePayload,
}

impl Message {
    /// Creates a new message.
    pub fn new(request_id: RequestId, sender: NodeId, payload: MessagePayload) -> Self {
        Self {
            request_id,
            sender,
            payload,
        }
    }

    /// Returns the message type.
    pub fn message_type(&self) -> MessageType {
        self.payload.message_type()
    }
}

impl CanonicalEncode for Message {
    fn encode(&self, buf: &mut BytesMut) {
        self.request_id.encode(buf);
        self.sender.encode(buf);
        self.payload.encode(buf);
    }
}

impl CanonicalDecode for Message {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            request_id: RequestId::decode(buf)?,
            sender: NodeId::decode(buf)?,
            payload: MessagePayload::decode(buf)?,
        })
    }
}

/// Message payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    // DHT operations
    /// Ping request
    Ping,
    /// Pong response
    Pong,
    /// Find node request
    FindNode { target: NodeId },
    /// Find node response
    FindNodeResponse { nodes: Vec<NodeInfo> },
    /// Store DHT record
    StoreRecord { record: DhtRecord },
    /// Store record response
    StoreRecordResponse { success: bool },
    /// Find value by key
    FindValue { key: [u8; 32] },
    /// Find value response (either value or closer nodes)
    FindValueResponse { result: FindValueResult },

    // Chunk operations
    /// Get chunk by ciphertext hash
    GetChunk { ciphertext_hash: CiphertextHash },
    /// Get chunk response
    GetChunkResponse { chunk: Option<StoredChunk> },
    /// Store a chunk
    StoreChunk { chunk: StoredChunk },
    /// Store chunk response
    StoreChunkResponse { success: bool },

    // Manifest operations
    /// Get manifest for object
    GetManifest {
        object_id: ObjectId,
        revision: Option<RevisionId>,
    },
    /// Get manifest response
    GetManifestResponse {
        manifest: Option<ManifestAnnouncement>,
    },
    /// Publish a manifest
    PublishManifest { announcement: ManifestAnnouncement },
    /// Publish manifest response
    PublishManifestResponse { success: bool },

    /// Error response
    Error { code: ErrorCode, message: String },
}

impl MessagePayload {
    /// Returns the message type for this payload.
    pub fn message_type(&self) -> MessageType {
        match self {
            MessagePayload::Ping => MessageType::Ping,
            MessagePayload::Pong => MessageType::Pong,
            MessagePayload::FindNode { .. } => MessageType::FindNode,
            MessagePayload::FindNodeResponse { .. } => MessageType::FindNodeResponse,
            MessagePayload::StoreRecord { .. } => MessageType::StoreRecord,
            MessagePayload::StoreRecordResponse { .. } => MessageType::StoreRecordResponse,
            MessagePayload::FindValue { .. } => MessageType::FindValue,
            MessagePayload::FindValueResponse { .. } => MessageType::FindValueResponse,
            MessagePayload::GetChunk { .. } => MessageType::GetChunk,
            MessagePayload::GetChunkResponse { .. } => MessageType::GetChunkResponse,
            MessagePayload::StoreChunk { .. } => MessageType::StoreChunk,
            MessagePayload::StoreChunkResponse { .. } => MessageType::StoreChunkResponse,
            MessagePayload::GetManifest { .. } => MessageType::GetManifest,
            MessagePayload::GetManifestResponse { .. } => MessageType::GetManifestResponse,
            MessagePayload::PublishManifest { .. } => MessageType::PublishManifest,
            MessagePayload::PublishManifestResponse { .. } => MessageType::PublishManifestResponse,
            MessagePayload::Error { .. } => MessageType::Error,
        }
    }
}

impl CanonicalEncode for MessagePayload {
    fn encode(&self, buf: &mut BytesMut) {
        self.message_type().tag().encode(buf);
        match self {
            MessagePayload::Ping => {}
            MessagePayload::Pong => {}
            MessagePayload::FindNode { target } => target.encode(buf),
            MessagePayload::FindNodeResponse { nodes } => nodes.encode(buf),
            MessagePayload::StoreRecord { record } => record.encode(buf),
            MessagePayload::StoreRecordResponse { success } => {
                (*success as u8).encode(buf);
            }
            MessagePayload::FindValue { key } => key.encode(buf),
            MessagePayload::FindValueResponse { result } => result.encode(buf),
            MessagePayload::GetChunk { ciphertext_hash } => ciphertext_hash.encode(buf),
            MessagePayload::GetChunkResponse { chunk } => chunk.encode(buf),
            MessagePayload::StoreChunk { chunk } => chunk.encode(buf),
            MessagePayload::StoreChunkResponse { success } => {
                (*success as u8).encode(buf);
            }
            MessagePayload::GetManifest {
                object_id,
                revision,
            } => {
                object_id.encode(buf);
                revision.encode(buf);
            }
            MessagePayload::GetManifestResponse { manifest } => manifest.encode(buf),
            MessagePayload::PublishManifest { announcement } => announcement.encode(buf),
            MessagePayload::PublishManifestResponse { success } => {
                (*success as u8).encode(buf);
            }
            MessagePayload::Error { code, message } => {
                (*code as u32).encode(buf);
                message.encode(buf);
            }
        }
    }
}

impl CanonicalDecode for MessagePayload {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let tag = u32::decode(buf)?;
        let msg_type = MessageType::from_tag(tag)?;

        Ok(match msg_type {
            MessageType::Ping => MessagePayload::Ping,
            MessageType::Pong => MessagePayload::Pong,
            MessageType::FindNode => MessagePayload::FindNode {
                target: NodeId::decode(buf)?,
            },
            MessageType::FindNodeResponse => MessagePayload::FindNodeResponse {
                nodes: Vec::<NodeInfo>::decode(buf)?,
            },
            MessageType::StoreRecord => MessagePayload::StoreRecord {
                record: DhtRecord::decode(buf)?,
            },
            MessageType::StoreRecordResponse => MessagePayload::StoreRecordResponse {
                success: u8::decode(buf)? != 0,
            },
            MessageType::FindValue => MessagePayload::FindValue {
                key: <[u8; 32]>::decode(buf)?,
            },
            MessageType::FindValueResponse => MessagePayload::FindValueResponse {
                result: FindValueResult::decode(buf)?,
            },
            MessageType::GetChunk => MessagePayload::GetChunk {
                ciphertext_hash: CiphertextHash::decode(buf)?,
            },
            MessageType::GetChunkResponse => MessagePayload::GetChunkResponse {
                chunk: Option::<StoredChunk>::decode(buf)?,
            },
            MessageType::StoreChunk => MessagePayload::StoreChunk {
                chunk: StoredChunk::decode(buf)?,
            },
            MessageType::StoreChunkResponse => MessagePayload::StoreChunkResponse {
                success: u8::decode(buf)? != 0,
            },
            MessageType::GetManifest => MessagePayload::GetManifest {
                object_id: ObjectId::decode(buf)?,
                revision: Option::<RevisionId>::decode(buf)?,
            },
            MessageType::GetManifestResponse => MessagePayload::GetManifestResponse {
                manifest: Option::<ManifestAnnouncement>::decode(buf)?,
            },
            MessageType::PublishManifest => MessagePayload::PublishManifest {
                announcement: ManifestAnnouncement::decode(buf)?,
            },
            MessageType::PublishManifestResponse => MessagePayload::PublishManifestResponse {
                success: u8::decode(buf)? != 0,
            },
            MessageType::Error => MessagePayload::Error {
                code: ErrorCode::from_tag(u32::decode(buf)?),
                message: String::decode(buf)?,
            },
        })
    }
}

/// Node information for DHT responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node identifier
    pub node_id: NodeId,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Public key for connection
    pub public_key: [u8; 32],
}

impl CanonicalEncode for NodeInfo {
    fn encode(&self, buf: &mut BytesMut) {
        self.node_id.encode(buf);
        self.addresses.encode(buf);
        self.public_key.encode(buf);
    }
}

impl CanonicalDecode for NodeInfo {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            node_id: NodeId::decode(buf)?,
            addresses: Vec::<String>::decode(buf)?,
            public_key: <[u8; 32]>::decode(buf)?,
        })
    }
}

/// Result of a FindValue operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindValueResult {
    /// Value found
    Found(DhtRecord),
    /// Value not found, but here are closer nodes
    Nodes(Vec<NodeInfo>),
}

impl CanonicalEncode for FindValueResult {
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            FindValueResult::Found(record) => {
                0u8.encode(buf);
                record.encode(buf);
            }
            FindValueResult::Nodes(nodes) => {
                1u8.encode(buf);
                nodes.encode(buf);
            }
        }
    }
}

impl CanonicalDecode for FindValueResult {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let tag = u8::decode(buf)?;
        match tag {
            0 => Ok(FindValueResult::Found(DhtRecord::decode(buf)?)),
            1 => Ok(FindValueResult::Nodes(Vec::<NodeInfo>::decode(buf)?)),
            _ => Err(DecodeError::InvalidEnumTag(tag as u32)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::new(
            12345,
            NodeId::random(),
            MessagePayload::Ping,
        );

        let encoded = msg.to_vec();
        let decoded = Message::from_bytes(&encoded).unwrap();

        assert_eq!(msg.request_id, decoded.request_id);
        assert_eq!(msg.sender, decoded.sender);
        assert!(matches!(decoded.payload, MessagePayload::Ping));
    }

    #[test]
    fn test_find_node_message() {
        let target = NodeId::random();
        let msg = Message::new(
            1,
            NodeId::random(),
            MessagePayload::FindNode { target },
        );

        let encoded = msg.to_vec();
        let decoded = Message::from_bytes(&encoded).unwrap();

        if let MessagePayload::FindNode { target: decoded_target } = decoded.payload {
            assert_eq!(target, decoded_target);
        } else {
            panic!("Expected FindNode payload");
        }
    }

    #[test]
    fn test_error_message() {
        let msg = Message::new(
            1,
            NodeId::random(),
            MessagePayload::Error {
                code: ErrorCode::NotFound,
                message: "Chunk not found".to_string(),
            },
        );

        let encoded = msg.to_vec();
        let decoded = Message::from_bytes(&encoded).unwrap();

        if let MessagePayload::Error { code, message } = decoded.payload {
            assert_eq!(code, ErrorCode::NotFound);
            assert_eq!(message, "Chunk not found");
        } else {
            panic!("Expected Error payload");
        }
    }
}
