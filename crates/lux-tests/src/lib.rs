//! Integration and end-to-end tests for Lux.
//!
//! This crate provides:
//! - A multi-node test harness for spinning up test networks
//! - Integration tests for DHT, storage, and networking
//! - End-to-end tests for blob upload/download workflows

pub mod harness;
pub mod node;

pub use harness::TestNetwork;
pub use node::TestNode;
