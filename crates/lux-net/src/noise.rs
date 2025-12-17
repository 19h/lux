//! Noise NK protocol implementation per specification §12.3.
//!
//! Uses the NK pattern where:
//! - N: No static key for initiator (ephemeral only)
//! - K: Responder's static key is known to initiator
//!
//! # BLAKE3 Implementation Note
//!
//! Per specification §12.3, Lux uses BLAKE3 for the hash function in the Noise
//! protocol. However, the `snow` crate (our Noise implementation) doesn't
//! natively support BLAKE3 in its pattern parser.
//!
//! ## Workaround
//!
//! We use a custom `CryptoResolver` that intercepts the hash choice and
//! substitutes our BLAKE3 implementation. The pattern string uses "BLAKE2s"
//! for parsing compatibility, but the actual cryptographic operations use
//! BLAKE3.
//!
//! This approach is cryptographically sound because:
//! 1. BLAKE3 and BLAKE2s have compatible output sizes (32 bytes)
//! 2. BLAKE3 provides equivalent or better security properties
//! 3. The substitution is transparent to the protocol logic
//! 4. Both sides use the same implementation, ensuring interoperability
//!
//! ## Verification
//!
//! The `NOISE_PATTERN` constant reflects the actual algorithm used (BLAKE3),
//! while `INTERNAL_NOISE_PATTERN` is only used for `snow` crate compatibility.

use snow::params::NoiseParams;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;

/// Internal pattern string for `snow` crate compatibility.
///
/// Uses BLAKE2s in the pattern string because `snow` doesn't parse BLAKE3.
/// The actual hash function is BLAKE3, substituted via `LuxResolver`.
///
/// **Do not use this string for protocol identification** - use `NOISE_PATTERN` instead.
const INTERNAL_NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// The canonical Noise pattern name per specification §12.3.
///
/// This is the actual protocol identifier that reflects the cryptographic
/// algorithms in use:
/// - NK: No initiator static key, Known responder static key
/// - 25519: X25519 for Diffie-Hellman
/// - ChaChaPoly: ChaCha20-Poly1305 for AEAD
/// - BLAKE3: BLAKE3 for hashing (via custom resolver)
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE3";

/// Maximum message size for Noise transport.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// BLAKE3 hash implementation for Noise protocol.
struct Blake3Hash {
    hasher: blake3::Hasher,
}

impl Default for Blake3Hash {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Hash for Blake3Hash {
    fn name(&self) -> &'static str {
        "BLAKE3"
    }

    fn block_len(&self) -> usize {
        64 // BLAKE3 block size
    }

    fn hash_len(&self) -> usize {
        32 // Output 32 bytes for Noise compatibility
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize();
        let len = out.len().min(32);
        out[..len].copy_from_slice(&hash.as_bytes()[..len]);
    }
}

/// Custom crypto resolver that provides BLAKE3 support.
struct LuxResolver {
    default: DefaultResolver,
}

impl LuxResolver {
    fn new() -> Self {
        Self {
            default: DefaultResolver,
        }
    }
}

impl CryptoResolver for LuxResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.default.resolve_rng()
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn Dh>> {
        self.default.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn Hash>> {
        // Always use BLAKE3 per specification §12.3, regardless of what
        // the pattern string says. The pattern uses BLAKE2s for parsing
        // compatibility but we substitute BLAKE3 here.
        match choice {
            snow::params::HashChoice::Blake2s => Some(Box::new(Blake3Hash::default())),
            _ => self.default.resolve_hash(choice),
        }
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn Cipher>> {
        self.default.resolve_cipher(choice)
    }
}

/// Creates a Noise builder with BLAKE3 support per specification §12.3.
fn create_builder() -> Result<Builder<'static>, NoiseError> {
    // Parse the internal pattern (using BLAKE2s for compatibility)
    // but the LuxResolver will substitute BLAKE3 for all hash operations.
    let params: NoiseParams = INTERNAL_NOISE_PATTERN.parse()?;
    Ok(Builder::with_resolver(params, Box::new(LuxResolver::new())))
}

/// Noise session errors.
#[derive(Debug, Error)]
pub enum NoiseError {
    /// Handshake not complete
    #[error("Handshake not complete")]
    HandshakeIncomplete,

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Snow error
    #[error("Noise error: {0}")]
    Snow(#[from] snow::Error),
}

/// Noise session state.
pub enum NoiseState {
    /// Handshake in progress
    Handshake(Box<HandshakeState>),
    /// Transport established
    Transport(Box<TransportState>),
}

/// Noise NK session for encrypted communication.
pub struct NoiseSession {
    state: NoiseState,
    is_initiator: bool,
    remote_static: Option<[u8; 32]>,
}

impl NoiseSession {
    /// Creates a new initiator session.
    ///
    /// The responder's static public key must be known.
    pub fn new_initiator(responder_static: &[u8; 32]) -> Result<Self, NoiseError> {
        let builder = create_builder()?;
        let keypair = builder.generate_keypair()?;

        let handshake = builder
            .local_private_key(&keypair.private)
            .remote_public_key(responder_static)
            .build_initiator()?;

        Ok(Self {
            state: NoiseState::Handshake(Box::new(handshake)),
            is_initiator: true,
            remote_static: Some(*responder_static),
        })
    }

    /// Creates a new responder session.
    pub fn new_responder(local_private_key: &[u8; 32]) -> Result<Self, NoiseError> {
        let builder = create_builder()?;

        let handshake = builder
            .local_private_key(local_private_key)
            .build_responder()?;

        Ok(Self {
            state: NoiseState::Handshake(Box::new(handshake)),
            is_initiator: false,
            remote_static: None,
        })
    }

    /// Returns true if the handshake is complete.
    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.state, NoiseState::Transport(_))
    }

    /// Returns true if this is the initiator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Returns the remote static public key (if known).
    pub fn remote_static(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }

    /// Writes a handshake message.
    pub fn write_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &mut self.state {
            NoiseState::Handshake(hs) => {
                let mut buf = vec![0u8; payload.len() + 128];
                let len = hs.write_message(payload, &mut buf)?;
                buf.truncate(len);
                Ok(buf)
            }
            NoiseState::Transport(_) => Err(NoiseError::InvalidState(
                "Handshake already complete".to_string(),
            )),
        }
    }

    /// Reads a handshake message.
    pub fn read_handshake(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &mut self.state {
            NoiseState::Handshake(hs) => {
                let mut buf = vec![0u8; message.len()];
                let len = hs.read_message(message, &mut buf)?;
                buf.truncate(len);
                Ok(buf)
            }
            NoiseState::Transport(_) => Err(NoiseError::InvalidState(
                "Handshake already complete".to_string(),
            )),
        }
    }

    /// Completes the handshake and transitions to transport mode.
    pub fn complete_handshake(&mut self) -> Result<(), NoiseError> {
        // Check if already in transport mode
        if matches!(self.state, NoiseState::Transport(_)) {
            return Err(NoiseError::InvalidState(
                "Already in transport mode".to_string(),
            ));
        }

        // Take ownership using a temporary state
        // We use a dummy initiator for the swap - it will be replaced immediately
        let dummy_builder = create_builder()?;
        let dummy_keypair = dummy_builder.generate_keypair()?;
        let dummy_hs = create_builder()?
            .local_private_key(&dummy_keypair.private)
            .remote_public_key(&[0u8; 32])
            .build_initiator()?;
        let dummy_state = NoiseState::Handshake(Box::new(dummy_hs));

        let old_state = std::mem::replace(&mut self.state, dummy_state);

        match old_state {
            NoiseState::Handshake(hs) => {
                if !hs.is_handshake_finished() {
                    self.state = NoiseState::Handshake(hs);
                    return Err(NoiseError::HandshakeIncomplete);
                }
                let transport = hs.into_transport_mode()?;
                self.state = NoiseState::Transport(Box::new(transport));
                Ok(())
            }
            NoiseState::Transport(_) => {
                unreachable!("Already checked above");
            }
        }
    }

    /// Encrypts a message for transport.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &mut self.state {
            NoiseState::Transport(ts) => {
                let mut buf = vec![0u8; plaintext.len() + 16]; // 16 bytes for AEAD tag
                let len = ts
                    .write_message(plaintext, &mut buf)
                    .map_err(|e| NoiseError::EncryptionFailed(e.to_string()))?;
                buf.truncate(len);
                Ok(buf)
            }
            NoiseState::Handshake(_) => Err(NoiseError::HandshakeIncomplete),
        }
    }

    /// Decrypts a message from transport.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &mut self.state {
            NoiseState::Transport(ts) => {
                let mut buf = vec![0u8; ciphertext.len()];
                let len = ts
                    .read_message(ciphertext, &mut buf)
                    .map_err(|e| NoiseError::DecryptionFailed(e.to_string()))?;
                buf.truncate(len);
                Ok(buf)
            }
            NoiseState::Handshake(_) => Err(NoiseError::HandshakeIncomplete),
        }
    }
}

/// Generates a new static keypair for Noise.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), NoiseError> {
    let builder = create_builder()?;
    let keypair = builder.generate_keypair()?;

    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&keypair.private);
    public.copy_from_slice(&keypair.public);

    Ok((private, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        // Generate responder's keypair
        let (responder_private, responder_public) = generate_keypair().unwrap();

        // Create sessions
        let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
        let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

        // Initiator -> Responder (e, es)
        let msg1 = initiator.write_handshake(&[]).unwrap();
        responder.read_handshake(&msg1).unwrap();

        // Responder -> Initiator (e, ee)
        let msg2 = responder.write_handshake(&[]).unwrap();
        initiator.read_handshake(&msg2).unwrap();

        // Complete handshake
        initiator.complete_handshake().unwrap();
        responder.complete_handshake().unwrap();

        assert!(initiator.is_handshake_complete());
        assert!(responder.is_handshake_complete());
    }

    #[test]
    fn test_noise_transport() {
        let (responder_private, responder_public) = generate_keypair().unwrap();

        let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
        let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

        // Complete handshake
        let msg1 = initiator.write_handshake(&[]).unwrap();
        responder.read_handshake(&msg1).unwrap();
        let msg2 = responder.write_handshake(&[]).unwrap();
        initiator.read_handshake(&msg2).unwrap();
        initiator.complete_handshake().unwrap();
        responder.complete_handshake().unwrap();

        // Test encryption/decryption
        let plaintext = b"Hello, Lux!";
        let ciphertext = initiator.encrypt(plaintext).unwrap();
        let decrypted = responder.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Test reverse direction
        let plaintext2 = b"Hello back!";
        let ciphertext2 = responder.encrypt(plaintext2).unwrap();
        let decrypted2 = initiator.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext2.as_slice(), decrypted2.as_slice());
    }
}
