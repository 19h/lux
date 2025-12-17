//! QUIC transport implementation per specification §12.1.
//!
//! QUIC provides the primary transport with built-in:
//! - Encryption (via TLS 1.3)
//! - Multiplexing
//! - Connection migration
//! - Congestion control

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode};
use lux_core::NodeId;
use lux_proto::messages::Message;
use parking_lot::RwLock;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig as QuinnTransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::connection::Connection;
use crate::noise::NoiseSession;
use crate::transport::{Transport, TransportConfig, TransportError};
use crate::PeerInfo;

/// QUIC transport implementation.
pub struct QuicTransport {
    /// Configuration
    config: TransportConfig,
    /// Local node ID
    local_id: NodeId,
    /// Local static keypair for Noise
    local_private_key: [u8; 32],
    local_public_key: [u8; 32],
    /// QUIC endpoint
    endpoint: RwLock<Option<Endpoint>>,
    /// Active connections (Arc for sharing with acceptor task)
    connections: Arc<RwLock<HashMap<NodeId, QuicConnection>>>,
    /// Noise sessions for encryption
    noise_sessions: RwLock<HashMap<NodeId, NoiseSession>>,
    /// Incoming message channel
    incoming_tx: mpsc::Sender<(NodeId, Message)>,
    incoming_rx: RwLock<Option<mpsc::Receiver<(NodeId, Message)>>>,
}

/// A QUIC connection to a peer.
struct QuicConnection {
    /// Connection metadata
    inner: Connection,
    /// QUIC connection handle
    quinn_conn: quinn::Connection,
}

impl QuicTransport {
    /// Creates a new QUIC transport.
    pub fn new(
        config: TransportConfig,
        local_id: NodeId,
        local_private_key: [u8; 32],
        local_public_key: [u8; 32],
    ) -> Self {
        let (tx, rx) = mpsc::channel(1024);

        Self {
            config,
            local_id,
            local_private_key,
            local_public_key,
            endpoint: RwLock::new(None),
            connections: Arc::new(RwLock::new(HashMap::new())),
            noise_sessions: RwLock::new(HashMap::new()),
            incoming_tx: tx,
            incoming_rx: RwLock::new(Some(rx)),
        }
    }

    /// Returns the local public key.
    pub fn local_public_key(&self) -> &[u8; 32] {
        &self.local_public_key
    }

    /// Starts the transport listener.
    pub async fn start(&self) -> Result<(), TransportError> {
        // Generate self-signed certificate for QUIC
        let (cert, key) = generate_self_signed_cert()
            .map_err(|e| TransportError::Other(format!("Failed to generate cert: {}", e)))?;

        // Configure server
        let mut server_config = ServerConfig::with_single_cert(vec![cert.clone()], key.clone_key())
            .map_err(|e| TransportError::Other(format!("Server config error: {}", e)))?;

        // Configure transport parameters
        let mut transport = QuinnTransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        server_config.transport_config(Arc::new(transport));

        // Create endpoint
        let endpoint = Endpoint::server(server_config, self.config.listen_addr)
            .map_err(|e| TransportError::Other(format!("Failed to create endpoint: {}", e)))?;

        info!(addr = %self.config.listen_addr, "QUIC transport started");

        // Store endpoint
        *self.endpoint.write() = Some(endpoint.clone());

        // Spawn connection acceptor
        let incoming_tx = self.incoming_tx.clone();
        let local_private_key = self.local_private_key;
        let noise_sessions = Arc::new(RwLock::new(HashMap::new()));
        let noise_sessions_clone = noise_sessions.clone();
        let connections = Arc::clone(&self.connections);

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let incoming_tx = incoming_tx.clone();
                let local_private_key = local_private_key;
                let noise_sessions = noise_sessions_clone.clone();
                let connections = Arc::clone(&connections);

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let remote = conn.remote_address();
                            debug!("Accepted connection from {}", remote);

                            if let Err(e) = handle_connection(
                                conn,
                                local_private_key,
                                incoming_tx,
                                noise_sessions,
                                connections,
                            ).await {
                                warn!("Connection handler error: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                });
            }
        });

        Ok(())
    }

    /// Creates a client configuration.
    fn client_config() -> Result<ClientConfig, TransportError> {
        // For development, accept any certificate
        // In production, this should verify the peer's certificate
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TransportError::Other(format!("Client crypto config error: {}", e)))?
        ));

        let mut transport = QuinnTransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        config.transport_config(Arc::new(transport));

        Ok(config)
    }
}

/// Handles an incoming QUIC connection.
async fn handle_connection(
    conn: quinn::Connection,
    _local_private_key: [u8; 32],
    incoming_tx: mpsc::Sender<(NodeId, Message)>,
    noise_sessions: Arc<RwLock<HashMap<NodeId, NoiseSession>>>,
    connections: Arc<RwLock<HashMap<NodeId, QuicConnection>>>,
) -> Result<(), TransportError> {
    // Clone the connection for storing once we know the peer's node_id
    let conn_for_storage = conn.clone();
    let peer_registered = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Accept bidirectional streams for messages
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let incoming_tx = incoming_tx.clone();
                let noise_sessions = noise_sessions.clone();
                let connections = Arc::clone(&connections);
                let conn_for_storage = conn_for_storage.clone();
                let peer_registered = Arc::clone(&peer_registered);

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(
                        send,
                        recv,
                        incoming_tx,
                        noise_sessions,
                        connections,
                        conn_for_storage,
                        peer_registered,
                    ).await {
                        debug!("Stream handler error: {}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!("Connection closed by peer");
                break;
            }
            Err(e) => {
                warn!("Failed to accept stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Handles a bidirectional stream.
async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    incoming_tx: mpsc::Sender<(NodeId, Message)>,
    _noise_sessions: Arc<RwLock<HashMap<NodeId, NoiseSession>>>,
    connections: Arc<RwLock<HashMap<NodeId, QuicConnection>>>,
    conn: quinn::Connection,
    peer_registered: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), TransportError> {
    // Read message length (4 bytes, little-endian)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(TransportError::ReceiveFailed("Message too large".to_string()));
    }

    // Read message
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;

    // Decode message
    let mut data = Bytes::from(buf);
    let message = Message::decode(&mut data)
        .map_err(|e| TransportError::ReceiveFailed(format!("Decode error: {:?}", e)))?;

    let sender = message.sender;

    // Register this inbound connection if not already registered
    // This allows us to send messages back to the peer
    if !peer_registered.swap(true, std::sync::atomic::Ordering::SeqCst) {
        let mut conns = connections.write();
        if !conns.contains_key(&sender) {
            let mut quic_conn = QuicConnection {
                inner: Connection::new(sender),
                quinn_conn: conn,
            };
            quic_conn.inner.set_connected();
            conns.insert(sender, quic_conn);
            debug!(peer = %sender, "Registered inbound connection");
        }
    }

    // Send to handler
    incoming_tx
        .send((sender, message))
        .await
        .map_err(|_| TransportError::ReceiveFailed("Channel closed".to_string()))?;

    Ok(())
}

#[async_trait]
impl Transport for QuicTransport {
    fn local_addr(&self) -> SocketAddr {
        self.endpoint
            .read()
            .as_ref()
            .map(|e| e.local_addr().unwrap_or(self.config.listen_addr))
            .unwrap_or(self.config.listen_addr)
    }

    fn local_node_id(&self) -> &NodeId {
        &self.local_id
    }

    async fn connect(&self, peer: &PeerInfo) -> Result<(), TransportError> {
        if self.is_connected(&peer.node_id) {
            return Err(TransportError::AlreadyConnected);
        }

        // Get or create endpoint
        let endpoint = {
            let guard = self.endpoint.read();
            match guard.as_ref() {
                Some(e) => e.clone(),
                None => {
                    drop(guard);
                    // Create client-only endpoint
                    let (cert, key) = generate_self_signed_cert()
                        .map_err(|e| TransportError::Other(format!("Cert generation failed: {}", e)))?;

                    let mut server_config = ServerConfig::with_single_cert(vec![cert], key.clone_key())
                        .map_err(|e| TransportError::Other(e.to_string()))?;

                    let endpoint = Endpoint::server(server_config, "0.0.0.0:0".parse().unwrap())
                        .map_err(|e| TransportError::Other(e.to_string()))?;

                    *self.endpoint.write() = Some(endpoint.clone());
                    endpoint
                }
            }
        };

        // Connect to peer
        let client_config = Self::client_config()?;
        let connecting = endpoint
            .connect_with(client_config, peer.addresses[0], "lux")
            .map_err(|e: quinn::ConnectError| TransportError::ConnectionFailed(e.to_string()))?;
        let conn = connecting
            .await
            .map_err(|e: quinn::ConnectionError| TransportError::ConnectionFailed(e.to_string()))?;

        // Initialize Noise session
        let session = NoiseSession::new_initiator(&peer.static_key)
            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

        // Clone connection for the receive handler
        let conn_for_handler = conn.clone();

        // Store connection
        let mut quic_conn = QuicConnection {
            inner: Connection::new(peer.node_id),
            quinn_conn: conn,
        };
        quic_conn.inner.set_connected();

        self.connections.write().insert(peer.node_id, quic_conn);
        self.noise_sessions.write().insert(peer.node_id, session);

        // Spawn handler to receive messages on this outbound connection
        // This allows the remote peer to send messages back to us
        let incoming_tx = self.incoming_tx.clone();
        let noise_sessions = Arc::new(RwLock::new(HashMap::new()));
        let connections = Arc::clone(&self.connections);
        let local_private_key = self.local_private_key;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                conn_for_handler,
                local_private_key,
                incoming_tx,
                noise_sessions,
                connections,
            ).await {
                debug!("Outbound connection handler error: {}", e);
            }
        });

        debug!(peer = %peer.node_id, "Connected to peer via QUIC");
        Ok(())
    }

    async fn disconnect(&self, node_id: &NodeId) -> Result<(), TransportError> {
        let mut connections = self.connections.write();
        let mut sessions = self.noise_sessions.write();

        if let Some(mut conn) = connections.remove(node_id) {
            conn.inner.set_disconnected();
            conn.quinn_conn.close(0u32.into(), b"disconnect");
            sessions.remove(node_id);
            debug!(peer = %node_id, "Disconnected from peer");
            Ok(())
        } else {
            Err(TransportError::NotConnected)
        }
    }

    fn is_connected(&self, node_id: &NodeId) -> bool {
        self.connections
            .read()
            .get(node_id)
            .map(|c| c.inner.is_active())
            .unwrap_or(false)
    }

    async fn send(&self, node_id: &NodeId, message: Message) -> Result<(), TransportError> {
        // Encode message
        let mut buf = BytesMut::new();
        message.encode(&mut buf);

        // Get connection
        let conn = {
            let conns = self.connections.read();
            conns
                .get(node_id)
                .ok_or(TransportError::NotConnected)?
                .quinn_conn
                .clone()
        };

        // Open stream and send
        let (mut send, _recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Write length prefix
        let len = (buf.len() as u32).to_le_bytes();
        send.write_all(&len)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Write message
        send.write_all(&buf)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        send.finish()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Update stats
        if let Some(conn) = self.connections.write().get_mut(node_id) {
            conn.inner.record_sent(buf.len() as u64 + 4);
        }

        debug!(peer = %node_id, size = buf.len(), "Sent message via QUIC");
        Ok(())
    }

    async fn recv(&self) -> Result<(NodeId, Message), TransportError> {
        let mut rx = {
            let mut rx_guard = self.incoming_rx.write();
            rx_guard
                .take()
                .ok_or(TransportError::ReceiveFailed("Receiver taken".to_string()))?
        };

        let result = rx.recv().await;

        {
            let mut rx_guard = self.incoming_rx.write();
            *rx_guard = Some(rx);
        }

        result.ok_or(TransportError::ReceiveFailed("Channel closed".to_string()))
    }

    fn connection_count(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|c| c.inner.is_active())
            .count()
    }
}

/// Generates a self-signed certificate for QUIC.
fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn std::error::Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(vec!["lux".to_string()])?;
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);
    Ok((cert, key.into()))
}

/// Skip server certificate verification (for development).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_keypair;

    #[tokio::test]
    async fn test_quic_transport_creation() {
        let config = TransportConfig::default();
        let local_id = NodeId::random();
        let (private, public) = generate_keypair().unwrap();

        let transport = QuicTransport::new(config, local_id, private, public);
        assert_eq!(*transport.local_node_id(), local_id);
    }

    #[tokio::test]
    async fn test_quic_transport_start() {
        let mut config = TransportConfig::default();
        config.listen_addr = "127.0.0.1:0".parse().unwrap();
        let local_id = NodeId::random();
        let (private, public) = generate_keypair().unwrap();

        let transport = QuicTransport::new(config, local_id, private, public);
        let result = transport.start().await;
        assert!(result.is_ok());

        // Verify endpoint was created
        assert!(transport.endpoint.read().is_some());
    }

    #[tokio::test]
    async fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());
    }
}
