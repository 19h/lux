//! Intensive data exchange integration tests.
//!
//! Tests for actual message passing and data transfer between nodes:
//! - Ping/pong exchanges
//! - Chunk transfer between nodes
//! - Concurrent message exchanges
//! - High-throughput messaging
//! - Multi-node broadcast scenarios
//! - Request-response patterns

use std::sync::Arc;
use std::time::Duration;

use lux_core::{CiphertextHash, NodeId};
use lux_proto::messages::MessagePayload;
use lux_proto::storage::StoredChunk;
use lux_tests::{TestNetwork, TestNode};
use lux_tests::node::TestNodeConfig;
use tokio::sync::Barrier;

/// Default timeout for message operations.
const MSG_TIMEOUT: Duration = Duration::from_secs(5);

/// Initialize tracing for tests.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lux_tests=debug,lux_net=debug")
        .with_test_writer()
        .try_init();
}

// ============================================================================
// Basic Ping/Pong Tests
// ============================================================================

#[tokio::test]
async fn test_ping_pong_exchange() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();

    // Connect nodes
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Node 0 sends ping to Node 1
    let request_id = nodes[0].send_ping(&nodes[1].node_id).await.unwrap();

    // Node 1 receives ping
    let (from, recv_id) = nodes[1].recv_ping(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[0].node_id);
    assert_eq!(recv_id, request_id);

    // Node 1 sends pong
    nodes[1].send_pong(&nodes[0].node_id, recv_id).await.unwrap();

    // Node 0 receives pong
    let (from, pong_id) = nodes[0].recv_pong(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[1].node_id);
    assert_eq!(pong_id, request_id);
}

#[tokio::test]
async fn test_multiple_ping_pong_rounds() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Perform 10 ping-pong exchanges
    for i in 0..10 {
        let request_id = nodes[0].send_ping(&nodes[1].node_id).await.unwrap();
        let (_, recv_id) = nodes[1].recv_ping(MSG_TIMEOUT).await.unwrap();
        assert_eq!(recv_id, request_id);

        nodes[1].send_pong(&nodes[0].node_id, recv_id).await.unwrap();
        let (_, pong_id) = nodes[0].recv_pong(MSG_TIMEOUT).await.unwrap();
        assert_eq!(pong_id, request_id, "Round {} failed", i);
    }
}

#[tokio::test]
async fn test_bidirectional_ping_pong() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // First, node 0 sends a ping to node 1 to establish bidirectional awareness
    let init_id = nodes[0].send_ping(&nodes[1].node_id).await.unwrap();
    let (_, recv_id) = nodes[1].recv_ping(MSG_TIMEOUT).await.unwrap();
    assert_eq!(recv_id, init_id);
    nodes[1].send_pong(&nodes[0].node_id, recv_id).await.unwrap();
    let _ = nodes[0].recv_pong(MSG_TIMEOUT).await.unwrap();

    // Now both nodes can communicate bidirectionally
    // Node 1 sends ping to Node 0
    let id1 = nodes[1].send_ping(&nodes[0].node_id).await.unwrap();
    let (from, recv_id) = nodes[0].recv_ping(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[1].node_id);
    assert_eq!(recv_id, id1);

    nodes[0].send_pong(&nodes[1].node_id, recv_id).await.unwrap();
    let (from, pong_id) = nodes[1].recv_pong(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[0].node_id);
    assert_eq!(pong_id, id1);
}

// ============================================================================
// Chunk Transfer Tests
// ============================================================================

#[tokio::test]
async fn test_chunk_transfer_between_nodes() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a test chunk
    let chunk_data = vec![0xAB; 1024];
    let chunk = StoredChunk::new([0x42; 24], chunk_data.clone());
    let chunk_hash = chunk.ciphertext_hash();

    // Node 0 sends chunk to Node 1
    let request_id = nodes[0].send_chunk(&nodes[1].node_id, chunk.clone()).await.unwrap();

    // Node 1 receives the chunk
    let (from, recv_id, received_chunk) = nodes[1].recv_store_chunk(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[0].node_id);
    assert_eq!(recv_id, request_id);
    assert_eq!(received_chunk.ciphertext_hash(), chunk_hash);
    assert_eq!(received_chunk.ciphertext_with_tag, chunk_data);

    // Node 1 acknowledges
    nodes[1].send_store_chunk_response(&nodes[0].node_id, recv_id, true).await.unwrap();
}

#[tokio::test]
async fn test_chunk_request_response() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create and store a chunk on Node 1
    let chunk_data = vec![0xCD; 2048];
    let chunk = StoredChunk::new([0x24; 24], chunk_data.clone());
    let chunk_hash = chunk.ciphertext_hash();
    nodes[1].store_chunk(&chunk).unwrap();

    // Node 0 requests the chunk from Node 1
    let request_id = nodes[0].request_chunk(&nodes[1].node_id, chunk_hash).await.unwrap();

    // Node 1 receives the request
    let (from, recv_id, requested_hash) = nodes[1].recv_get_chunk(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[0].node_id);
    assert_eq!(recv_id, request_id);
    assert_eq!(requested_hash, chunk_hash);

    // Node 1 retrieves and sends the chunk
    let stored_chunk = nodes[1].get_chunk(&requested_hash).unwrap();
    nodes[1].send_chunk_response(&nodes[0].node_id, recv_id, stored_chunk).await.unwrap();

    // Node 0 receives the response
    let (from, resp_id, received_chunk) = nodes[0].recv_chunk_response(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[1].node_id);
    assert_eq!(resp_id, request_id);

    let received_chunk = received_chunk.expect("Chunk should be present");
    assert_eq!(received_chunk.ciphertext_hash(), chunk_hash);
    assert_eq!(received_chunk.ciphertext_with_tag, chunk_data);
}

#[tokio::test]
async fn test_large_chunk_transfer() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a large chunk (64 KB)
    let chunk_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let chunk = StoredChunk::new([0x42; 24], chunk_data.clone());

    // Transfer it
    let request_id = nodes[0].send_chunk(&nodes[1].node_id, chunk.clone()).await.unwrap();

    let (_, recv_id, received_chunk) = nodes[1].recv_store_chunk(MSG_TIMEOUT).await.unwrap();
    assert_eq!(recv_id, request_id);
    assert_eq!(received_chunk.ciphertext_with_tag, chunk_data);
}

#[tokio::test]
async fn test_multiple_chunk_transfers() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send 20 chunks sequentially
    for i in 0..20u8 {
        let chunk_data = vec![i; 512];
        let chunk = StoredChunk::new([i; 24], chunk_data.clone());

        let request_id = nodes[0].send_chunk(&nodes[1].node_id, chunk).await.unwrap();

        let (_, recv_id, received_chunk) = nodes[1].recv_store_chunk(MSG_TIMEOUT).await.unwrap();
        assert_eq!(recv_id, request_id);
        assert_eq!(received_chunk.ciphertext_with_tag, chunk_data, "Chunk {} mismatch", i);
    }
}

// ============================================================================
// High-Throughput Tests
// ============================================================================

#[tokio::test]
async fn test_rapid_fire_messages() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send 100 pings as fast as possible
    let mut request_ids = Vec::new();
    for _ in 0..100 {
        let id = nodes[0].send_ping(&nodes[1].node_id).await.unwrap();
        request_ids.push(id);
    }

    // Receive all pings
    let mut received_count = 0;
    for _ in 0..100 {
        match nodes[1].recv_ping(MSG_TIMEOUT).await {
            Ok((from, _)) => {
                assert_eq!(from, nodes[0].node_id);
                received_count += 1;
            }
            Err(e) => {
                // Some messages might be lost under heavy load
                eprintln!("Missed message: {:?}", e);
            }
        }
    }

    // Should receive most messages
    assert!(
        received_count >= 90,
        "Expected at least 90 messages, got {}",
        received_count
    );
}

#[tokio::test]
async fn test_concurrent_chunk_transfers() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn multiple concurrent chunk sends
    let node0 = Arc::clone(&nodes[0]);
    let node1_id = nodes[1].node_id;

    let send_tasks: Vec<_> = (0..10u8)
        .map(|i| {
            let node = Arc::clone(&node0);
            tokio::spawn(async move {
                let chunk_data = vec![i; 1024];
                let chunk = StoredChunk::new([i; 24], chunk_data);
                node.send_chunk(&node1_id, chunk).await
            })
        })
        .collect();

    // Wait for all sends
    for task in send_tasks {
        task.await.unwrap().unwrap();
    }

    // Receive all chunks
    let mut received_chunks = 0;
    for _ in 0..10 {
        if nodes[1].recv_store_chunk(MSG_TIMEOUT).await.is_ok() {
            received_chunks += 1;
        }
    }

    assert!(
        received_chunks >= 8,
        "Expected at least 8 chunks, got {}",
        received_chunks
    );
}

// ============================================================================
// Multi-Node Broadcast Tests
// ============================================================================

#[tokio::test]
async fn test_broadcast_to_all_peers() {
    init_tracing();

    let network = TestNetwork::with_nodes(4).await.unwrap();

    // Node 0 connects to all others (star topology)
    for i in 1..4 {
        network.nodes()[0].connect_to(&network.nodes()[i]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let nodes = network.nodes();
    let sender = &nodes[0];

    // Broadcast a chunk to all peers
    let chunk_data = vec![0xFF; 256];
    let chunk = StoredChunk::new([0x99; 24], chunk_data.clone());

    for peer in &nodes[1..] {
        sender.send_chunk(&peer.node_id, chunk.clone()).await.unwrap();
    }

    // All peers should receive the chunk
    for peer in &nodes[1..] {
        let result = peer.recv_store_chunk(MSG_TIMEOUT).await;
        assert!(result.is_ok(), "Peer {} failed to receive chunk", peer.node_id);
        let (from, _, received_chunk) = result.unwrap();
        assert_eq!(from, sender.node_id);
        assert_eq!(received_chunk.ciphertext_with_tag, chunk_data);
    }
}

#[tokio::test]
async fn test_mesh_ping_all() {
    init_tracing();

    let network = TestNetwork::with_nodes(4).await.unwrap();
    network.connect_mesh().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let nodes = network.nodes();

    // Node 0 pings all other nodes
    let sender = &nodes[0];
    let mut request_ids = Vec::new();

    for peer in &nodes[1..] {
        let id = sender.send_ping(&peer.node_id).await.unwrap();
        request_ids.push((peer.node_id, id));
    }

    // All peers respond
    for peer in &nodes[1..] {
        let result = peer.recv_ping(MSG_TIMEOUT).await;
        if let Ok((from, req_id)) = result {
            assert_eq!(from, sender.node_id);
            peer.send_pong(&sender.node_id, req_id).await.unwrap();
        }
    }

    // Sender receives all pongs
    for _ in 0..3 {
        let result = sender.recv_pong(MSG_TIMEOUT).await;
        assert!(result.is_ok(), "Failed to receive pong");
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_sustained_message_stream() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let node0 = Arc::clone(&nodes[0]);
    let node1 = Arc::clone(&nodes[1]);
    let node1_id = nodes[1].node_id;
    let node0_id = nodes[0].node_id;

    // Sender task: send messages continuously
    let sender = tokio::spawn(async move {
        let mut sent = 0;
        for i in 0..50u8 {
            let chunk = StoredChunk::new([i; 24], vec![i; 100]);
            if node0.send_chunk(&node1_id, chunk).await.is_ok() {
                sent += 1;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        sent
    });

    // Receiver task: receive messages continuously
    let receiver = tokio::spawn(async move {
        let mut received = 0;
        let timeout = Duration::from_secs(10);
        let deadline = tokio::time::Instant::now() + timeout;

        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(
                Duration::from_millis(200),
                node1.recv_store_chunk(Duration::from_millis(100))
            ).await {
                Ok(Ok((from, _, _))) => {
                    assert_eq!(from, node0_id);
                    received += 1;
                    if received >= 50 {
                        break;
                    }
                }
                _ => continue,
            }
        }
        received
    });

    let (sent, received) = tokio::join!(sender, receiver);
    let sent = sent.unwrap();
    let received = received.unwrap();

    assert!(sent >= 45, "Expected to send at least 45, sent {}", sent);
    assert!(
        received >= 40,
        "Expected to receive at least 40, received {}",
        received
    );
}

#[tokio::test]
async fn test_chunk_store_and_retrieve_cycle() {
    init_tracing();

    let network = TestNetwork::with_nodes(3).await.unwrap();
    network.connect_mesh().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let nodes = network.nodes();

    // Node 0 creates and stores chunks locally
    let mut chunks = Vec::new();
    for i in 0..5u8 {
        let chunk_data = vec![i; 512 + (i as usize * 100)];
        let chunk = StoredChunk::new([i; 24], chunk_data);
        let hash = chunk.ciphertext_hash();
        nodes[0].store_chunk(&chunk).unwrap();
        chunks.push((hash, chunk));
    }

    // Node 0 sends all chunks to Node 1
    for (_, chunk) in &chunks {
        nodes[0].send_chunk(&nodes[1].node_id, chunk.clone()).await.unwrap();
    }

    // Node 1 receives and stores all chunks
    for _ in 0..5 {
        let (_, _, chunk) = nodes[1].recv_store_chunk(MSG_TIMEOUT).await.unwrap();
        nodes[1].store_chunk(&chunk).unwrap();
    }

    // Verify Node 1 has all chunks
    for (hash, original) in &chunks {
        let stored = nodes[1].get_chunk(hash).unwrap().unwrap();
        assert_eq!(stored.ciphertext_with_tag, original.ciphertext_with_tag);
    }

    // First, establish communication between Node 2 and Node 1
    // (Node 1 connected to Node 2 in mesh, but Node 2 needs to receive a message first)
    nodes[1].send_ping(&nodes[2].node_id).await.unwrap();
    let (_, req_id) = nodes[2].recv_ping(MSG_TIMEOUT).await.unwrap();
    nodes[2].send_pong(&nodes[1].node_id, req_id).await.unwrap();
    let _ = nodes[1].recv_pong(MSG_TIMEOUT).await.unwrap();

    // Now Node 2 can request chunks from Node 1
    for (hash, original) in &chunks {
        nodes[2].request_chunk(&nodes[1].node_id, *hash).await.unwrap();

        let (from, req_id, requested_hash) = nodes[1].recv_get_chunk(MSG_TIMEOUT).await.unwrap();
        assert_eq!(from, nodes[2].node_id);
        assert_eq!(requested_hash, *hash);

        let chunk = nodes[1].get_chunk(&requested_hash).unwrap();
        nodes[1].send_chunk_response(&nodes[2].node_id, req_id, chunk).await.unwrap();

        let (_, _, received_chunk) = nodes[2].recv_chunk_response(MSG_TIMEOUT).await.unwrap();
        let received_chunk = received_chunk.unwrap();
        assert_eq!(received_chunk.ciphertext_with_tag, original.ciphertext_with_tag);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_request_nonexistent_chunk() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Request a chunk that doesn't exist
    let nonexistent_hash = CiphertextHash::new([0xDE; 32]);
    nodes[0].request_chunk(&nodes[1].node_id, nonexistent_hash).await.unwrap();

    let (from, req_id, _) = nodes[1].recv_get_chunk(MSG_TIMEOUT).await.unwrap();
    assert_eq!(from, nodes[0].node_id);

    // Node 1 doesn't have the chunk
    let chunk = nodes[1].get_chunk(&nonexistent_hash).unwrap();
    assert!(chunk.is_none());

    // Send empty response
    nodes[1].send_chunk_response(&nodes[0].node_id, req_id, None).await.unwrap();

    let (_, _, received_chunk) = nodes[0].recv_chunk_response(MSG_TIMEOUT).await.unwrap();
    assert!(received_chunk.is_none(), "Should receive None for nonexistent chunk");
}

#[tokio::test]
async fn test_message_timeout() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to receive without any message being sent - should timeout
    let result = nodes[0].recv_message(Duration::from_millis(100)).await;
    assert!(result.is_err(), "Should timeout when no message");
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

#[tokio::test]
async fn test_chunk_data_integrity() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create chunk with specific data pattern
    let chunk_data: Vec<u8> = (0..1000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    let chunk = StoredChunk::new([0x42; 24], chunk_data.clone());
    let original_hash = chunk.ciphertext_hash();

    // Send and receive
    nodes[0].send_chunk(&nodes[1].node_id, chunk).await.unwrap();
    let (_, _, received) = nodes[1].recv_store_chunk(MSG_TIMEOUT).await.unwrap();

    // Verify integrity
    assert_eq!(received.ciphertext_hash(), original_hash);
    assert_eq!(received.ciphertext_with_tag.len(), chunk_data.len());

    for (i, (a, b)) in chunk_data.iter().zip(received.ciphertext_with_tag.iter()).enumerate() {
        assert_eq!(a, b, "Byte mismatch at position {}", i);
    }
}

#[tokio::test]
async fn test_sequential_unique_request_ids() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send multiple messages and verify request IDs are unique and sequential
    let mut ids = Vec::new();
    for _ in 0..10 {
        let id = nodes[0].send_ping(&nodes[1].node_id).await.unwrap();
        ids.push(id);
    }

    // All IDs should be unique
    let mut sorted_ids = ids.clone();
    sorted_ids.sort();
    sorted_ids.dedup();
    assert_eq!(ids.len(), sorted_ids.len(), "Request IDs should be unique");

    // IDs should be sequential
    for i in 1..ids.len() {
        assert!(ids[i] > ids[i - 1], "Request IDs should be increasing");
    }
}
