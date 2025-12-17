//! Lux Daemon - Background service for the Lux distributed filesystem.
//!
//! Provides:
//! - DHT participation and routing
//! - Chunk storage and serving
//! - Manifest publishing and retrieval
//! - Network connectivity

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use tokio::select;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use lux_core::encoding::{CanonicalDecode, CanonicalEncode};
use lux_core::{NetworkKey, NodeId, SigningKey};
use lux_dht::routing::NodeEntry;
use lux_dht::service::{DhtCommand, DhtConfig, DhtService};
use lux_proto::messages::{Message, MessagePayload, NodeInfo};
use lux_store::{BlobStore, StoreConfig};

/// Lux daemon service.
#[derive(Parser)]
#[command(name = "luxd")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Configuration file path
    #[arg(short, long, default_value = "~/.lux/config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (default)
    Run {
        /// Listen address
        #[arg(short, long)]
        listen: Option<SocketAddr>,

        /// Run in foreground
        #[arg(long)]
        foreground: bool,
    },

    /// Show daemon status
    Status,

    /// Stop a running daemon
    Stop,

    /// Reload configuration
    Reload,
}

/// Daemon configuration.
#[derive(Debug, Clone)]
struct DaemonConfig {
    /// Node identity key path
    identity_file: PathBuf,
    /// Network key (shared secret for network authentication)
    network_key: NetworkKey,
    /// Listen address
    listen_addr: SocketAddr,
    /// Bootstrap nodes
    bootstrap_nodes: Vec<String>,
    /// Data directory
    data_dir: PathBuf,
    /// Maximum cache size in bytes
    max_cache_bytes: u64,
    /// DHT refresh interval
    dht_refresh_secs: u64,
    /// Maintenance interval
    maintenance_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            identity_file: PathBuf::from("~/.lux/identity.key"),
            network_key: NetworkKey::random(),
            listen_addr: "0.0.0.0:4242".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            data_dir: PathBuf::from("~/.lux/data"),
            max_cache_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            dht_refresh_secs: 3600,
            maintenance_secs: 60,
        }
    }
}

/// Load configuration from TOML file.
fn load_config(path: &PathBuf) -> Result<DaemonConfig> {
    let path = expand_tilde(path);

    if !path.exists() {
        info!("No config file found at {:?}, using defaults", path);
        return Ok(DaemonConfig::default());
    }

    let content = std::fs::read_to_string(&path)
        .context("Failed to read config file")?;

    let toml: toml::Value = content.parse()
        .context("Failed to parse config file")?;

    let mut config = DaemonConfig::default();

    // Parse [node] section
    if let Some(node) = toml.get("node") {
        if let Some(identity) = node.get("identity_file").and_then(|v| v.as_str()) {
            config.identity_file = PathBuf::from(identity);
        }
    }

    // Parse [network] section
    if let Some(network) = toml.get("network") {
        if let Some(listen) = network.get("listen").and_then(|v| v.as_str()) {
            config.listen_addr = listen.parse()
                .context("Invalid listen address")?;
        }
        if let Some(bootstrap) = network.get("bootstrap").and_then(|v| v.as_array()) {
            config.bootstrap_nodes = bootstrap
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
    }

    // Parse [storage] section
    if let Some(storage) = toml.get("storage") {
        if let Some(data_dir) = storage.get("data_dir").and_then(|v| v.as_str()) {
            config.data_dir = PathBuf::from(data_dir);
        }
        if let Some(max_cache_gb) = storage.get("max_cache_gb").and_then(|v| v.as_integer()) {
            config.max_cache_bytes = max_cache_gb as u64 * 1024 * 1024 * 1024;
        }
    }

    Ok(config)
}

/// Expand ~ to home directory.
fn expand_tilde(path: &PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&s[2..]);
        }
    }
    path.clone()
}

/// Load or generate node identity.
fn load_identity(path: &PathBuf) -> Result<(SigningKey, NodeId)> {
    let path = expand_tilde(path);

    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .context("Failed to read identity file")?;

        // Parse the key file
        for line in content.lines() {
            if line.starts_with("private: ") {
                let hex_key = &line[9..];
                let key_bytes = hex::decode(hex_key)
                    .context("Invalid private key hex")?;

                if key_bytes.len() != 32 {
                    anyhow::bail!("Invalid private key length");
                }

                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key_bytes);

                let signing_key = SigningKey::from_bytes(&bytes);
                let public_key = signing_key.public_key();
                let node_id = NodeId::from_public_key(&public_key);

                return Ok((signing_key, node_id));
            }
        }

        anyhow::bail!("No private key found in identity file");
    } else {
        // Generate new identity
        info!("Generating new node identity");
        let signing_key = SigningKey::random();
        let public_key = signing_key.public_key();
        let node_id = NodeId::from_public_key(&public_key);

        // Save identity
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create identity directory")?;
        }

        let key_data = format!(
            "# Lux Identity Key\n# Node ID: {}\nprivate: {}\npublic: {}\n",
            node_id.to_hex(),
            hex::encode(signing_key.as_bytes()),
            hex::encode(public_key)
        );
        std::fs::write(&path, key_data)
            .context("Failed to write identity file")?;

        info!("Saved new identity to {:?}", path);
        Ok((signing_key, node_id))
    }
}

/// The main daemon service.
struct Daemon {
    config: DaemonConfig,
    signing_key: SigningKey,
    node_id: NodeId,
    dht_service: Arc<DhtService>,
    blob_store: Arc<BlobStore>,
}

impl Daemon {
    /// Creates a new daemon with the given configuration.
    fn new(config: DaemonConfig) -> Result<(Self, mpsc::Receiver<DhtCommand>)> {
        // Load identity
        let (signing_key, node_id) = load_identity(&config.identity_file)?;
        info!("Node ID: {}", node_id.to_hex());

        // Initialize storage
        let data_dir = expand_tilde(&config.data_dir);
        std::fs::create_dir_all(&data_dir)
            .context("Failed to create data directory")?;

        let store_config = StoreConfig::new(data_dir.clone());
        store_config.create_dirs()
            .context("Failed to create storage directories")?;

        let blob_store = Arc::new(BlobStore::open(&store_config.blobs_path())
            .map_err(|e| anyhow::anyhow!("Failed to open blob store: {}", e))?);

        // Initialize DHT
        let dht_config = DhtConfig::new(node_id, config.network_key.clone());
        let (dht_service, dht_rx) = DhtService::new(dht_config);
        let dht_service = Arc::new(dht_service);

        Ok((
            Self {
                config,
                signing_key,
                node_id,
                dht_service,
                blob_store,
            },
            dht_rx,
        ))
    }

    /// Returns the node ID.
    fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Bootstraps from known nodes.
    async fn bootstrap(&self) -> Result<()> {
        if self.config.bootstrap_nodes.is_empty() {
            info!("No bootstrap nodes configured");
            return Ok(());
        }

        info!("Bootstrapping from {} nodes", self.config.bootstrap_nodes.len());

        for addr_str in &self.config.bootstrap_nodes {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    info!("Connecting to bootstrap node: {}", addr);

                    // Connect and perform initial lookup
                    match self.connect_and_bootstrap(addr).await {
                        Ok(nodes_found) => {
                            info!("Bootstrap from {} successful, found {} nodes", addr, nodes_found);
                        }
                        Err(e) => {
                            warn!("Bootstrap from {} failed: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Invalid bootstrap address {}: {}", addr_str, e);
                }
            }
        }

        Ok(())
    }

    /// Handles an incoming DHT command.
    async fn handle_command(&self, cmd: DhtCommand) {
        match cmd {
            DhtCommand::Bootstrap(node_info) => {
                info!("Bootstrap request from {:?}", node_info.node_id.to_hex());
                let entry = NodeEntry::new(
                    node_info.node_id,
                    node_info.addresses,
                    node_info.public_key,
                );
                self.dht_service.add_node(entry);
            }

            DhtCommand::FindNode(target, reply_tx) => {
                debug!("FindNode request for {}", target.to_hex());
                let nodes: Vec<NodeInfo> = self
                    .dht_service
                    .closest_nodes(&target)
                    .into_iter()
                    .map(|e| NodeInfo {
                        node_id: e.node_id,
                        addresses: e.addresses,
                        public_key: e.public_key,
                    })
                    .collect();
                let _ = reply_tx.send(nodes).await;
            }

            DhtCommand::Store(record) => {
                debug!("Store record request");
                if let Err(e) = self.dht_service.store_record(record) {
                    warn!("Failed to store record: {}", e);
                }
            }

            DhtCommand::FindValue(key, reply_tx) => {
                debug!("FindValue request for key");
                // Try to find the value locally
                let node_id = NodeId::new(key);
                let result = self.dht_service.get_node(&node_id).map(|node| {
                    use lux_proto::dht::{DhtRecord, DhtRecordBody};
                    DhtRecord::new(
                        DhtRecordBody::Node(node),
                        &self.config.network_key,
                    )
                });
                let _ = reply_tx.send(result).await;
            }

            DhtCommand::Announce(announcement) => {
                info!("Node announcement: {}", announcement.node_id.to_hex());
                use lux_proto::dht::{DhtRecord, DhtRecordBody};
                let record = DhtRecord::new(
                    DhtRecordBody::Node(announcement),
                    &self.config.network_key,
                );
                if let Err(e) = self.dht_service.store_record(record) {
                    warn!("Failed to store announcement: {}", e);
                }
            }

            DhtCommand::Shutdown => {
                info!("Shutdown command received");
            }
        }
    }

    /// Handles an incoming network message.
    fn handle_message(&self, from: NodeId, msg: Message) -> Option<Message> {
        debug!(
            "Message from {}: {:?}",
            from.to_hex(),
            std::mem::discriminant(&msg.payload)
        );

        // Handle chunk-related messages locally
        match &msg.payload {
            MessagePayload::GetChunk { ciphertext_hash } => {
                match self.blob_store.chunk_store().get(ciphertext_hash) {
                    Ok(chunk) => {
                        return Some(Message::new(
                            msg.request_id,
                            self.node_id,
                            MessagePayload::GetChunkResponse { chunk },
                        ));
                    }
                    Err(e) => {
                        return Some(Message::new(
                            msg.request_id,
                            self.node_id,
                            MessagePayload::Error {
                                code: lux_proto::messages::ErrorCode::Unknown,
                                message: e.to_string(),
                            },
                        ));
                    }
                }
            }

            MessagePayload::StoreChunk { chunk } => {
                match self.blob_store.chunk_store().put(chunk) {
                    Ok(_) => {
                        return Some(Message::new(
                            msg.request_id,
                            self.node_id,
                            MessagePayload::StoreChunkResponse { success: true },
                        ));
                    }
                    Err(e) => {
                        warn!("Failed to store chunk: {}", e);
                        return Some(Message::new(
                            msg.request_id,
                            self.node_id,
                            MessagePayload::StoreChunkResponse { success: false },
                        ));
                    }
                }
            }

            _ => {}
        }

        // Delegate to DHT service for other messages
        self.dht_service.handle_message(msg)
    }

    /// Connects to a bootstrap node and performs initial DHT lookup.
    async fn connect_and_bootstrap(&self, addr: SocketAddr) -> Result<usize> {
        // For bootstrap, we send a FindNode for our own ID
        // This populates our routing table with nearby nodes

        // Create a FindNode message for our own ID
        let request_id = rand::random();
        let msg = Message::new(
            request_id,
            self.node_id,
            MessagePayload::FindNode {
                target: self.node_id,
            },
        );

        // Encode the message
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);

        // Send FindNode via UDP to bootstrap node
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .context("Failed to bind UDP socket")?;
        socket.send_to(&buf, addr).await
            .context("Failed to send bootstrap message")?;

        debug!("Sent FindNode to {}: {} bytes", addr, buf.len());

        Ok(0)
    }

    /// Runs periodic maintenance.
    fn maintenance(&self) {
        debug!("Running maintenance");
        self.dht_service.maintenance();

        // Republish our node announcement
        if let Err(e) = self.republish_node_announcement() {
            warn!("Failed to republish node announcement: {}", e);
        }
    }

    /// Republishes our node announcement to the DHT.
    fn republish_node_announcement(&self) -> Result<()> {
        // Node announcement is typically republished every hour
        // to ensure other nodes know we're still online
        debug!("Republishing node announcement");
        Ok(())
    }

    /// Prints daemon status.
    fn print_status(&self) {
        println!("Lux Daemon Status");
        println!("=================");
        println!();
        println!("Node ID: {}", self.node_id.to_hex());
        println!("Listen: {}", self.config.listen_addr);
        println!();
        println!("DHT Statistics:");
        println!("  Routing table entries: {}", self.dht_service.routing_table().len());
        let record_stats = self.dht_service.record_store().stats();
        println!("  Node records: {}", record_stats.node_count);
        println!("  Manifest records: {}", record_stats.manifest_count);
        println!("  Chunk holder records: {}", record_stats.chunk_holder_count);
        println!();
        println!("Storage:");
        let stats = self.blob_store.chunk_store().stats();
        println!("  Chunks stored: {}", stats.chunks_stored);
        println!("  Bytes stored: {}", stats.bytes_stored);
        println!("  Data directory: {:?}", expand_tilde(&self.config.data_dir));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber).context("Failed to set up logging")?;

    // Load configuration
    let mut config = load_config(&cli.config)?;

    match cli.command.unwrap_or(Commands::Run {
        listen: None,
        foreground: true,
    }) {
        Commands::Run { listen, foreground } => {
            // Override listen address if specified
            if let Some(addr) = listen {
                config.listen_addr = addr;
            }

            info!("Starting Lux daemon");
            info!("Listen address: {}", config.listen_addr);
            info!("Data directory: {:?}", expand_tilde(&config.data_dir));

            // Create daemon
            let (daemon, mut dht_rx) = Daemon::new(config.clone())?;
            let daemon = Arc::new(daemon);

            // Bootstrap
            daemon.bootstrap().await?;

            // Create maintenance interval
            let mut maintenance_interval = interval(Duration::from_secs(config.maintenance_secs));

            // Create shutdown signal handler
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

            // Spawn signal handler
            let shutdown_tx_clone = shutdown_tx.clone();
            tokio::spawn(async move {
                match signal::ctrl_c().await {
                    Ok(()) => {
                        info!("Received shutdown signal");
                        let _ = shutdown_tx_clone.send(()).await;
                    }
                    Err(e) => {
                        error!("Failed to listen for shutdown signal: {}", e);
                    }
                }
            });

            println!("Lux daemon running");
            println!("  Node ID: {}", daemon.node_id().to_hex());
            println!("  Listen: {}", config.listen_addr);
            println!();
            println!("Press Ctrl+C to stop");

            // Main event loop
            loop {
                select! {
                    // Handle DHT commands
                    Some(cmd) = dht_rx.recv() => {
                        match cmd {
                            DhtCommand::Shutdown => {
                                info!("Shutdown requested via command");
                                break;
                            }
                            cmd => {
                                daemon.handle_command(cmd).await;
                            }
                        }
                    }

                    // Run maintenance
                    _ = maintenance_interval.tick() => {
                        daemon.maintenance();
                    }

                    // Handle shutdown
                    _ = shutdown_rx.recv() => {
                        info!("Shutting down");
                        break;
                    }
                }
            }

            info!("Daemon stopped");
        }

        Commands::Status => {
            // Try to connect to running daemon
            // For now, just show local status
            let (daemon, _) = Daemon::new(config)?;
            daemon.print_status();
        }

        Commands::Stop => {
            println!("Stop command not yet implemented");
            println!("Use Ctrl+C to stop the daemon or kill the process");
        }

        Commands::Reload => {
            println!("Reload command not yet implemented");
        }
    }

    Ok(())
}

/// Network listener that accepts incoming connections.
async fn network_listener(
    daemon: Arc<Daemon>,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind(daemon.config.listen_addr)
        .await
        .context("Failed to bind UDP socket")?;

    info!("Listening on {}", daemon.config.listen_addr);

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        debug!("Received {} bytes from {}", len, addr);

                        // Decode and handle message
                        let mut data = bytes::Bytes::copy_from_slice(&buf[..len]);
                        match Message::decode(&mut data) {
                            Ok(msg) => {
                                let peer_id = msg.sender;
                                if let Some(response) = daemon.handle_message(peer_id, msg) {
                                    let mut response_buf = BytesMut::new();
                                    response.encode(&mut response_buf);
                                    if let Err(e) = socket.send_to(&response_buf, addr).await {
                                        warn!("Failed to send response to {}: {}", addr, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode message from {}: {:?}", addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Socket receive error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Network listener shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Handles a connection from a peer with message framing.
async fn handle_connection(
    daemon: Arc<Daemon>,
    peer_id: NodeId,
    mut message_rx: mpsc::Receiver<Message>,
    message_tx: mpsc::Sender<Message>,
) {
    info!("Connection established with {}", peer_id.to_hex());

    while let Some(msg) = message_rx.recv().await {
        debug!(
            "Received message {} from {}",
            msg.request_id,
            peer_id.to_hex()
        );

        if let Some(response) = daemon.handle_message(peer_id, msg) {
            if message_tx.send(response).await.is_err() {
                warn!("Failed to send response, connection closed");
                break;
            }
        }
    }

    info!("Connection closed: {}", peer_id.to_hex());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_tilde() {
        let path = PathBuf::from("~/.lux/config.toml");
        let expanded = expand_tilde(&path);

        if let Some(home) = dirs::home_dir() {
            assert!(expanded.starts_with(&home));
            assert!(expanded.ends_with(".lux/config.toml"));
        }
    }

    #[test]
    fn test_default_config() {
        let config = DaemonConfig::default();
        assert_eq!(config.listen_addr.port(), 4242);
        assert!(config.bootstrap_nodes.is_empty());
    }
}
