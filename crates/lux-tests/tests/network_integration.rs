//! Network integration tests.
//!
//! Tests for the full networking stack including:
//! - QUIC transport
//! - Multi-node connectivity
//! - Connection management

use std::time::Duration;

use lux_core::NodeId;
use lux_net::transport::Transport;
use lux_tests::{TestNetwork, TestNode};
use lux_tests::node::TestNodeConfig;

/// Initialize tracing for tests.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lux_tests=debug,lux_net=debug")
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn test_single_node_start() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    let addr = node.addr().await.unwrap();
    assert!(addr.port() > 0, "Node should bind to a valid port");
}

#[tokio::test]
async fn test_two_node_connection() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();

    // Connect node 0 to node 1
    nodes[0].connect_to(&nodes[1]).await.unwrap();

    // Give connection time to establish
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify connection
    assert!(nodes[0].connection_count() >= 1, "Node 0 should have at least 1 connection");
}

#[tokio::test]
async fn test_mesh_topology_three_nodes() {
    init_tracing();

    let network = TestNetwork::with_nodes(3).await.unwrap();
    network.connect_mesh().await.unwrap();

    // Give connections time to establish
    tokio::time::sleep(Duration::from_millis(100)).await;

    // In a mesh of 3 nodes, we make 3 outbound connections:
    // node0->node1, node0->node2, node1->node2
    // connection_count only tracks outbound connections
    let total = network.total_connections();
    assert!(total >= 3, "Expected at least 3 outbound connections, got {}", total);
}

#[tokio::test]
async fn test_ring_topology_four_nodes() {
    init_tracing();

    let network = TestNetwork::with_nodes(4).await.unwrap();
    network.connect_ring().await.unwrap();

    // Each node connects to next, forming a ring
    assert!(network.total_connections() >= 4);
}

#[tokio::test]
async fn test_star_topology_five_nodes() {
    init_tracing();

    let network = TestNetwork::with_nodes(5).await.unwrap();
    network.connect_star().await.unwrap();

    // Give connections time to establish
    tokio::time::sleep(Duration::from_millis(100)).await;

    // In star topology, spokes connect to hub (not hub to spokes)
    // So we have 4 outbound connections total (from spokes to hub)
    let total = network.total_connections();
    assert!(total >= 4, "Expected at least 4 outbound connections, got {}", total);
}

#[tokio::test]
async fn test_node_reconnection() {
    init_tracing();

    let network = TestNetwork::with_nodes(2).await.unwrap();
    let nodes = network.nodes();

    // Connect
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify connected
    assert!(nodes[0].connection_count() >= 1);

    // Disconnect
    nodes[0].transport.disconnect(&nodes[1].node_id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reconnect
    nodes[0].connect_to(&nodes[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify reconnected
    assert!(nodes[0].connection_count() >= 1);
}

#[tokio::test]
async fn test_many_nodes_connectivity() {
    init_tracing();

    // Create a larger network
    let network = TestNetwork::with_nodes(10).await.unwrap();

    // Connect in ring topology (less connections than mesh)
    network.connect_ring().await.unwrap();

    // Verify all nodes have connections
    for (i, node) in network.nodes().iter().enumerate() {
        assert!(
            node.connection_count() >= 1,
            "Node {} should have at least 1 connection",
            i
        );
    }
}

#[tokio::test]
async fn test_peer_info_generation() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    let peer_info = node.peer_info().await.unwrap();

    assert_eq!(peer_info.node_id, node.node_id);
    assert!(!peer_info.addresses.is_empty());
    assert_eq!(peer_info.static_key, *node.static_key());
}

#[tokio::test]
async fn test_unique_node_ids() {
    init_tracing();

    let network = TestNetwork::with_nodes(5).await.unwrap();

    // Collect all node IDs
    let mut ids: Vec<NodeId> = network.nodes().iter().map(|n| n.node_id).collect();
    let original_len = ids.len();

    // Remove duplicates
    ids.sort_by_key(|id| id.0);
    ids.dedup_by_key(|id| id.0);

    // All IDs should be unique
    assert_eq!(ids.len(), original_len, "All node IDs should be unique");
}

#[tokio::test]
async fn test_network_key_shared() {
    init_tracing();

    let network = TestNetwork::with_nodes(3).await.unwrap();

    // All nodes should have the same network key
    let expected_key = &network.network_key;
    for node in network.nodes() {
        assert_eq!(&node.network_key, expected_key, "All nodes should share the same network key");
    }
}

#[tokio::test]
async fn test_connection_count_consistency() {
    init_tracing();

    let network = TestNetwork::with_nodes(3).await.unwrap();
    network.connect_mesh().await.unwrap();

    // In mesh: node0<->node1, node0<->node2, node1<->node2
    // Each connection is counted once per node, so total = 2*3 = 6
    // But connection_count returns outbound connections, so may vary

    let total = network.total_connections();
    assert!(total >= 3 && total <= 6, "Total connections should be between 3 and 6");
}

/// Test that tests can run concurrently without port conflicts.
#[tokio::test]
async fn test_concurrent_networks() {
    init_tracing();

    // Create two separate networks
    let (network1, network2) = tokio::join!(
        TestNetwork::with_nodes(2),
        TestNetwork::with_nodes(2)
    );

    let network1 = network1.unwrap();
    let network2 = network2.unwrap();

    // Connect each network internally
    let (result1, result2) = tokio::join!(
        network1.connect_mesh(),
        network2.connect_mesh()
    );

    result1.unwrap();
    result2.unwrap();

    // Both networks should work independently
    assert!(network1.total_connections() >= 1);
    assert!(network2.total_connections() >= 1);
}
