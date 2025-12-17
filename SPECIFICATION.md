# Lux: Distributed Resilient Filesystem

## Technical Specification v1.1

**ProtocolVersion:** `major = 1`, `minor = 0`
**CryptoVersion:** `V1`

### Conformance Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174.

---

## Revision Summary

| Version | Changes |
|---------|---------|
| v1.0 | Integrated high-level architectural vision with normative protocol specification. Resolved 72 internal inconsistencies. |
| v1.1 | Added **Project Structure** (§18) to define the modular architecture and workspace layout. |

---

# Part I: Architecture Overview

## 1. Introduction

### 1.1 Purpose and Scope

Lux is a decentralized, content-addressed filesystem that provides persistent, encrypted, and versioned storage across a mesh of autonomous nodes. This specification defines the complete protocol suite required for interoperable implementations, including cryptographic primitives, data structures, network protocols, and operational semantics.

### 1.2 Design Objectives

Lux addresses three fundamental limitations in contemporary data storage systems:

**Elimination of Central Authority Dependence.** Conventional cloud storage requires trust in specific providers to remain operational, solvent, and politically neutral. Lux distributes data across a mesh of autonomous nodes, ensuring data availability persists independent of any single entity's status.

**Global Deduplication through Content Addressing.** Redundant storage of identical data across isolated systems consumes substantial resources. Lux treats data as unique mathematical artifacts identified by cryptographic hashes, enabling network-wide deduplication while preserving privacy guarantees.

**Capability-Based Access Control.** Traditional secure file sharing requires complex key management infrastructure or delegation of decryption authority to third parties. In Lux, possession of a URI constitutes both the locator and the access capability; the network transports only encrypted artifacts without knowledge of their contents.

### 1.3 Architectural Principles

**Content Addressing.** All data is identified by cryptographic hashes of its contents, providing integrity verification and enabling deduplication.

**Convergent Encryption.** Identical plaintext produces identical ciphertext at the blob level, enabling deduplication across users without compromising confidentiality against non-guessing adversaries.

**Capability URIs.** Access rights are encoded directly in URIs. Possession of a URI grants the corresponding access level; no separate authentication infrastructure is required.

**Distributed State.** Network state is maintained across a Kademlia-derived DHT. No node possesses complete knowledge; consensus emerges from distributed agreement.

**Self-Healing Redundancy.** Storage commitments are maintained through autonomous monitoring and repair. Node departures trigger automatic re-replication to preserve redundancy guarantees.

---

## 2. System Model

### 2.1 Network Topology

The Lux network comprises autonomous nodes that collectively maintain a distributed hash table for metadata and a content-addressed blob store for encrypted data. Nodes participate in multiple roles:

**Client Nodes.** Mount Lux URIs as local filesystems, issue read/write requests, and maintain local caches.

**Storage Nodes.** Accept storage leases, persist encrypted chunks, and respond to retrieval requests.

**Routing Nodes.** Participate in DHT operations, relay messages between nodes lacking direct connectivity, and propagate announcements.

A single node MAY fulfill multiple roles simultaneously.

### 2.2 Trust Model

**Zero-Knowledge Storage.** Storage nodes possess no information about the data they hold beyond encrypted byte sequences. They cannot determine filenames, file types, ownership, or content.

**Capability-Based Authorization.** Read access requires possession of the URI (which encodes the decryption key). Write access to mutable objects requires possession of the corresponding private signing key.

**Network Membership.** Participation in DHT operations requires possession of a network key, which authenticates all DHT messages via MAC.

### 2.3 Addressing Scheme

Lux defines two URI schemes for addressing content:

```
lux:blob:<base64url(BlobId)>
lux:obj:<base64url(ObjectId)>:<base64url(CapabilitySecret)>[:<RevisionId>]
```

**Blob URIs** address immutable, content-identified data. The `BlobId` is derived from the plaintext content, enabling global deduplication.

**Object URIs** address mutable, versioned data. The `ObjectId` is a random identifier; the `CapabilitySecret` provides decryption capability. An optional `RevisionId` suffix addresses specific historical versions.

### 2.4 Data Lifecycle

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Plaintext  │───▶│   Chunked   │───▶│  Encrypted  │───▶│  Announced  │
│    File     │    │     DAG     │    │    Blobs    │    │   via DHT   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                  │                  │
                          ▼                  ▼                  ▼
                   ChunkId = H(pt)    CiphertextHash    ChunkHolders
                   DagRef = H(node)   = H(stored)       merger/lookup
```

---

## 3. Data Model

### 3.1 Content-Defined Chunking

Lux employs FastCDC (Fast Content-Defined Chunking) to partition files into variable-size chunks based on content boundaries rather than fixed offsets.

**Rationale.** Fixed-size chunking causes insertion or deletion of data to shift all subsequent chunk boundaries, invalidating downstream chunks for deduplication. Content-defined boundaries localize changes: modifying one region affects only adjacent chunks while preserving chunk identity elsewhere.

**Chunk Size Distribution.**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `CHUNK_MIN_SIZE` | 64 KiB | Prevents excessive fragmentation |
| `CHUNK_AVG_SIZE_TARGET` | 256 KiB | Balances dedup ratio and overhead |
| `CHUNK_MAX_SIZE` | 1 MiB | Bounds worst-case chunk size |

### 3.2 Merkle DAG Structure

Chunks are organized into a Merkle Directed Acyclic Graph:

**Leaf Nodes.** Contain references to encrypted data chunks, including plaintext identity (`ChunkId`), storage address (`CiphertextHash`), and integrity commitment.

**Internal Nodes.** Aggregate references to child nodes (leaves or other internals), enabling efficient addressing of large files through tree structures.

**Entry Nodes.** Represent named filesystem entries (files or directories) with associated metadata.

**Root Reference.** The `DagRef` of the root node uniquely identifies the complete state of a file or directory tree. Any modification to any chunk cascades hash changes upward to the root.

### 3.3 Versioning Model

Lux maintains immutable history through revision tracking:

**Revision Identifier.** Each modification to a mutable object increments a strictly monotonic `RevisionId`. This serves dual purposes: preventing replay attacks and enabling point-in-time recovery.

**Delta Efficiency.** Because chunk boundaries are content-defined, modifying a small portion of a large file typically affects only a few chunks. Unchanged chunks are referenced by their existing identifiers, achieving implicit delta compression.

**Historical Access.** Clients MAY request specific revisions by appending the revision identifier to the object URI. Storage of historical revisions is subject to retention policies.

---

## 4. Operational Model

### 4.1 Filesystem Interface

Lux presents network-resident data through standard operating system interfaces:

**Mount Semantics.** A Lux URI is mounted as a local directory via FUSE (Linux/macOS) or equivalent virtual filesystem interfaces. Standard filesystem operations (`open`, `read`, `write`, `readdir`, `stat`) are translated to Lux protocol operations.

**Demand Paging.** File content is fetched on demand at chunk granularity. Opening a multi-gigabyte file does not require downloading the complete file; only chunks intersecting requested byte ranges are retrieved.

**Write Buffering.** Modifications are accumulated locally and committed as atomic revisions. Write operations do not immediately propagate to the network; explicit sync or close operations trigger publication.

### 4.2 Caching Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Application Layer                  │
├─────────────────────────────────────────────────────┤
│                    VFS Interface                     │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  Hot Cache  │  │ Warm Cache  │  │ Cold Store  │ │
│  │   (Memory)  │  │   (SSD)     │  │  (Network)  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────┘
```

**Memory Cache.** Recently accessed decrypted chunks reside in memory for immediate access.

**Persistent Cache.** Chunks are persisted to local storage using LRU eviction. Cache size is configurable per-node.

**Prefetching.** Sequential access patterns trigger speculative prefetch of subsequent chunks to minimize latency.

### 4.3 Resilience Guarantees

Users specify desired redundancy levels for their data:

**Replication Factor.** The minimum number of independent storage nodes that MUST hold copies of each chunk (e.g., `min_replicas = 3`).

**Health Monitoring.** Clients (or designated custodian nodes) periodically query the DHT to verify that sufficient replicas remain available.

**Autonomous Repair.** When replica count falls below the specified minimum (due to node departure), the monitoring process retrieves data from remaining healthy replicas and uploads to new storage nodes, issuing fresh leases.

### 4.4 Data Governance

**Retention Policies.** Users MAY configure automatic pruning of historical revisions based on age or count limits.

**Lease Expiration.** Storage leases include time-to-live values. Unrenewal results in eventual garbage collection by storage nodes.

**Explicit Deletion.** Users MAY explicitly revoke leases and request deletion. Due to the distributed nature, deletion is eventually consistent rather than immediate.

---

# Part II: Protocol Specification

## 5. Cryptographic Primitives

### 5.1 Algorithm Suite

All implementations MUST support the following cryptographic algorithms:

| Function | Algorithm | Reference |
|----------|-----------|-----------|
| Key Derivation | HKDF-SHA-256 | RFC 5869 |
| Message Authentication | HMAC-SHA-256 | RFC 2104 |
| Authenticated Encryption | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03 |
| Hash | BLAKE3 (default mode, 256-bit) | BLAKE3 spec v1.0 |
| Digital Signature | Ed25519 (pure mode) | RFC 8032 |
| Key Agreement | X25519 | RFC 7748 |

### 5.2 HKDF-SHA-256

HKDF is instantiated per RFC 5869 with HMAC-SHA-256 as the PRF:

* Hash output length: 32 bytes
* Empty salt is treated as 32 zero bytes
* Info strings are raw ASCII bytes without length prefix or terminator

```rust
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = if salt.is_empty() {
        hmac_sha256(&[0u8; 32], ikm)
    } else {
        hmac_sha256(salt, ikm)
    };
    
    let n = (length + 31) / 32;
    assert!(n >= 1 && n <= 255);
    
    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();
    
    for i in 1..=n {
        let mut message = t.clone();
        message.extend_from_slice(info);
        message.push(i as u8);
        t = hmac_sha256(&prk, &message).to_vec();
        output.extend_from_slice(&t);
    }
    
    output.truncate(length);
    output
}
```

### 5.3 AEAD Semantics

XChaCha20-Poly1305 encryption and decryption:

* **Encrypt:** `(key[32], nonce[24], plaintext, aad) → ciphertext || tag[16]`
* **Decrypt:** `(key[32], nonce[24], ciphertext || tag[16], aad) → plaintext | error`

The nonce is NOT included in the AEAD output. Callers manage nonce storage separately.

### 5.4 BLAKE3 Parameterization

BLAKE3 is used in default hash mode with the following parameters:

* Mode: Default (not keyed, not KDF, no context string)
* Output length: 32 bytes (256 bits)
* Key: None

**Conformance Anchors.** Implementations MUST produce these digests:

```
BLAKE3("")      = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
BLAKE3([0x00])  = 2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213
BLAKE3([0x01])  = 48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b
BLAKE3([0xFF])  = 99d44d377bc5936d8cb7f5df90713d84c7587739b4724d3d2f9af1ee0e4c8efd
```

### 5.5 Ed25519 Signature Requirements

Ed25519 signatures MUST conform to RFC 8032 "pure" mode:

* Signatures are deterministic for a given key and message
* Verifiers MUST reject non-canonical signatures (invalid S range)
* Context strings are not used

---

## 6. Canonical Encoding

All data structures that participate in hashing, signing, or MAC computation MUST use canonical encoding to ensure deterministic byte representation across implementations.

### 6.1 Integer Encoding

| Type | Size | Format |
|------|------|--------|
| `u8`, `i8` | 1 byte | Identity / two's complement |
| `u16`, `i16` | 2 bytes | Little-endian |
| `u32`, `i32` | 4 bytes | Little-endian |
| `u64`, `i64` | 8 bytes | Little-endian |

### 6.2 Composite Type Encoding

**Fixed Arrays `[T; N]`.** Elements encoded consecutively without length prefix.

**Variable Sequences `Vec<T>`.** Length as `u32` followed by encoded elements. Encoding MUST fail if length exceeds `u32::MAX`.

**Strings.** Byte length as `u32` followed by UTF-8 bytes. No null terminator.

**Options.** `0x00` for `None`; `0x01` followed by encoded value for `Some`.

**Structs.** Fields encoded in declaration order without padding.

### 6.3 Enum Encoding

**Fieldless Enums.** Encoded as `u32` tag value (little-endian). Tag values are protocol constants, not language discriminants.

**Payloaded Enums.** Encoded as `u32` tag followed by payload fields in declaration order.

### 6.4 Map Encoding

Maps encode as:

1. Entry count as `u32`
2. Key-value pairs sorted by lexicographic order of encoded key bytes

Encoders MUST detect and reject encoded-key collisions (distinct keys producing identical encoded bytes).

### 6.5 Canonical Comparison

Deterministic ordering for tie-breaking compares canonical encodings lexicographically:

```rust
fn canonical_cmp<T: CanonicalEncode>(a: &T, b: &T) -> Ordering {
    a.to_bytes().cmp(&b.to_bytes())
}
```

---

## 7. Identifiers and Keys

### 7.1 Identifier Types

```rust
struct NodeId([u8; 32]);           // Node identity (typically H(pubkey))
struct ObjectId([u8; 32]);         // Mutable object identifier (random)
struct ChunkId([u8; 32]);          // BLAKE3(plaintext_chunk)
struct CiphertextHash([u8; 32]);   // BLAKE3(stored_bytes)
struct BlobId([u8; 32]);           // BLAKE3(full_plaintext)
struct DagRef([u8; 32]);           // BLAKE3(canonical_encode(DagNode)) or EMPTY
struct RevisionId(u64);            // Strictly monotonic per ObjectId
struct Timestamp(i64);             // Milliseconds since Unix epoch
```

### 7.2 Key Types

```rust
struct NetworkKey([u8; 32]);       // Network membership secret
struct CapabilitySecret([u8; 32]); // Object decryption capability
```

### 7.3 CryptoVersion

```rust
enum CryptoVersion {
    V1 = 1,  // Encodes as: 01 00 00 00
}
```

`CryptoVersion` is embedded in signed manifests to enable offline decryption across protocol versions.

---

## 8. Key Schedule

### 8.1 Derivation Constants

```rust
const INFO_NETWORK_MAC:    &[u8] = b"lux/v1/network-mac";
const INFO_MANIFEST_KEY:   &[u8] = b"lux/v1/manifest-key";
const INFO_MANIFEST_NONCE: &[u8] = b"lux/v1/manifest-nonce";
const INFO_CHUNK_KEY_BASE: &[u8] = b"lux/v1/chunk-key-base";
const INFO_CHUNK_KEY:      &[u8] = b"lux/v1/chunk-key";
const INFO_CHUNK_NONCE:    &[u8] = b"lux/v1/chunk-nonce";
const INFO_BLOB_KEY:       &[u8] = b"lux/v1/blob-key";
const INFO_BLOB_NONCE:     &[u8] = b"lux/v1/blob-nonce";
```

### 8.2 Key Derivation Table

| Key | IKM | Salt | Info | Length |
|-----|-----|------|------|--------|
| `network_mac_key` | NetworkKey | ∅ | `lux/v1/network-mac` | 32 |
| `manifest_key` | CapabilitySecret | ObjectId | `lux/v1/manifest-key` | 32 |
| `manifest_nonce` | CapabilitySecret | ObjectId ‖ RevisionId | `lux/v1/manifest-nonce` | 24 |
| `chunk_key_base` | CapabilitySecret | ObjectId | `lux/v1/chunk-key-base` | 32 |
| `chunk_key` | chunk_key_base | ChunkId | `lux/v1/chunk-key` | 32 |
| `chunk_nonce` | chunk_key_base | ChunkId | `lux/v1/chunk-nonce` | 24 |
| `blob_key` | BlobId | ∅ | `lux/v1/blob-key` | 32 |
| `blob_chunk_key` | blob_key | ChunkId | `lux/v1/chunk-key` | 32 |
| `blob_chunk_nonce` | blob_key | ChunkId | `lux/v1/chunk-nonce` | 24 |

### 8.3 AAD Formats (CryptoVersion::V1)

AAD formats are frozen per CryptoVersion. Modification requires a new version.

| Context | AAD | Size |
|---------|-----|------|
| Manifest | ObjectId | 32 bytes |
| Object Chunk | ObjectId ‖ ChunkId | 64 bytes |
| Blob Chunk | BlobId ‖ ChunkId | 64 bytes |

---

## 9. Storage Formats

### 9.1 StoredChunk

Encrypted chunks are serialized as:

```
┌────────────────────┬────────────────────┬──────────────┐
│    nonce (24)      │  ciphertext (var)  │   tag (16)   │
└────────────────────┴────────────────────┴──────────────┘
```

```rust
struct StoredChunk {
    nonce: [u8; 24],
    ciphertext_with_tag: Vec<u8>,  // ciphertext || tag[16]
}

impl StoredChunk {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError>;
    fn ciphertext_hash(&self) -> CiphertextHash {
        CiphertextHash(blake3(&self.to_bytes()))
    }
}
```

### 9.2 DAG Node Types

```rust
enum DagNode {
    Chunk(ChunkRefHashed),    // tag = 0
    Internal(InternalNode),   // tag = 1
    Entry(EntryNode),         // tag = 2
}

struct ChunkRefHashed {
    chunk_id: ChunkId,
    ciphertext_hash: CiphertextHash,
    commitment: CiphertextCommitment,
    offset: u64,
    size: u32,
}

struct InternalNode {
    children: Vec<DagRef>,
}

struct EntryNode {
    name: String,
    metadata: EntryMetadata,
    content: DagRef,
}

struct EntryMetadata {
    mode: u32,
    mtime: Timestamp,
}
```

### 9.3 Manifest Structure

```rust
struct ManifestBody {
    crypto_version: CryptoVersion,
    object_id: ObjectId,
    revision: RevisionId,
    content_root: DagRef,
    created_at: Timestamp,
    modified_at: Timestamp,
    origin: IdentityBinding,
}

struct Manifest {
    body: ManifestBody,
    signature: [u8; 64],  // Ed25519 over canonical_encode(body)
}
```

### 9.4 Well-Known Constants

| Name | Derivation | Value |
|------|------------|-------|
| `EMPTY_BLOB_ID` | BLAKE3("") | `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262` |
| `EMPTY_DAG_REF` | BLAKE3("lux/v1/empty-dag") | `98406f28ac2f17f4fa1b6f756a51a6b91b1d953f466a5e7730f9ee6acc7c3e59` |

---

## 10. Chunking Algorithm

### 10.1 FastCDC Parameters

```rust
const CHUNK_MIN_SIZE: usize = 65536;       // 64 KiB
const CHUNK_MAX_SIZE: usize = 1048576;     // 1 MiB
const CHUNK_AVG_SIZE_TARGET: usize = 262144; // 256 KiB (descriptive)

const MASK_S: u64 = (1 << 19) - 1;  // For positions < avg from chunk start
const MASK_L: u64 = (1 << 17) - 1;  // For positions >= avg from chunk start
```

### 10.2 Gear Table

```rust
fn gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    for i in 0..256 {
        let hash = blake3(&[i as u8]);
        table[i] = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    }
    table
}
```

**Spot Checks:**

```
GEAR[0]   = 0xf1611bf1dfde3a2d
GEAR[1]   = 0xe072c1bb1f72fc48
GEAR[255] = 0x6d93c57b374dd499
```

### 10.3 Boundary Semantics

Boundaries are **end-exclusive** indices. When a cut triggers at byte index `i`, the boundary is `i + 1`.

```rust
fn chunk(data: &[u8]) -> Vec<usize> {
    if data.is_empty() {
        return vec![0];  // Zero chunks, root = EMPTY_DAG_REF
    }
    
    let gear = gear_table();
    let mut boundaries = vec![0];
    let mut pos = 0;
    
    while pos < data.len() {
        if data.len() - pos <= CHUNK_MIN_SIZE {
            boundaries.push(data.len());
            break;
        }
        
        let mut hash = 0u64;
        let search_start = pos + CHUNK_MIN_SIZE;
        let search_end = (pos + CHUNK_MAX_SIZE).min(data.len());
        let mut found = false;
        
        for i in search_start..search_end {
            hash = (hash << 1).wrapping_add(gear[data[i] as usize]);
            let mask = if i - pos < CHUNK_AVG_SIZE_TARGET { MASK_S } else { MASK_L };
            
            if hash & mask == 0 {
                boundaries.push(i + 1);
                pos = i + 1;
                found = true;
                break;
            }
        }
        
        if !found {
            boundaries.push(search_end);
            pos = search_end;
        }
    }
    
    boundaries
}
```

---

## 11. DHT Protocol

### 11.1 Record Authentication

All DHT records are authenticated with the network MAC key:

```rust
struct DhtRecord<T> {
    body: T,
    mac: [u8; 32],  // HMAC(network_mac_key, canonical_encode(body))
}
```

Records with invalid MACs MUST be rejected before any further processing.

### 11.2 Record Types

| Type | DHT Key | Semantics |
|------|---------|-----------|
| `NodeAnnouncement` | NodeId | Supersede by (timestamp, bytes) |
| `ManifestAnnouncement` | ObjectId | Supersede by (revision, timestamp, bytes) |
| `ChunkHolders` | CiphertextHash | Merge (bounded set) |

### 11.3 Validation Gates

Before storage or merge, records MUST pass:

1. **MAC Gate:** Valid network membership MAC
2. **Size Gate:** Encoded size ≤ `DHT_MAX_RECORD_SIZE` (65536 bytes)
3. **Time Gate:** Timestamps within `MAX_CLOCK_SKEW` (300 seconds)
4. **Signature Gate:** Valid signatures where applicable
5. **Consistency Gate:** Internal field consistency (e.g., holder key matches lease)

### 11.4 Storage Lease

```rust
struct StorageLeaseBody {
    locator: ChunkLocator,
    commitment: CiphertextCommitment,
    holder: NodeId,
    issuer: NodeId,
    issued_at: Timestamp,
    expires_at: Timestamp,
}

struct StorageLease {
    body: StorageLeaseBody,
    issuer_signature: [u8; 64],
    holder_signature: [u8; 64],
}

struct ChunkAnnouncement {
    lease: StorageLease,
}
```

Both signatures are computed over `canonical_encode(StorageLeaseBody)`.

### 11.5 Chunk Holders Merge

Chunk holder sets use order-independent bounded merge:

**Quality Function:**

```rust
fn quality(ann: &ChunkAnnouncement) -> (i64, [u8;32], [u8;64], [u8;64]) {
    (
        ann.lease.body.expires_at.0,
        ann.lease.body.holder.0,
        ann.lease.issuer_signature,
        ann.lease.holder_signature,
    )
}
```

**Merge Algorithm:**

1. Per-holder: retain announcement with maximum quality
2. Bounded set: retain top-K holders by quality (K = 64)
3. Eviction: remove lowest-quality holder when at capacity

This construction is commutative, associative, and idempotent, guaranteeing convergence under network partitions.

---

## 12. Network Transport

### 12.1 Transport Stack

```
┌─────────────────────────────────────┐
│         Lux Protocol Messages        │
├─────────────────────────────────────┤
│         Noise NK Encryption          │
├─────────────────────────────────────┤
│    QUIC (primary) / TCP (fallback)   │
├─────────────────────────────────────┤
│         UDP / TCP / WebSocket        │
└─────────────────────────────────────┘
```

### 12.2 NAT Traversal

Lux employs aggressive connectivity establishment:

**STUN.** Nodes query STUN servers to determine their public address and NAT type.

**Hole Punching.** For nodes behind NAT, simultaneous connection attempts establish direct UDP paths.

**Relay Fallback.** When direct connectivity fails, traffic routes through mutually-reachable relay nodes. Relays observe only encrypted Noise traffic.

**Protocol Obfuscation.** Transport MAY be tunneled over HTTPS or WebSocket to traverse restrictive firewalls.

### 12.3 Connection Establishment

```
Initiator                              Responder
    │                                      │
    │──── Noise NK Handshake ────────────▶│
    │◀─── Noise NK Response ──────────────│
    │                                      │
    │◀═══ Encrypted Channel Established ══▶│
```

Post-handshake, all messages are encrypted with per-session keys derived from the Noise handshake.

---

## 13. Blob Format

### 13.1 Convergent Encryption

Blobs use convergent encryption for global deduplication:

* `BlobId = BLAKE3(full_plaintext)`
* `blob_key = HKDF(BlobId, salt=∅, info="lux/v1/blob-key", L=32)`

**Security Properties:**

| Property | Status |
|----------|--------|
| Confidentiality vs. passive observer | ✓ Provided |
| Confidentiality vs. content-guessing adversary | ✗ Not provided |
| Cross-blob chunk linkability | ✗ Not provided (by design) |

**Appropriate Use Cases:** Public datasets, software distribution, archives.

**Inappropriate Use Cases:** Confidential documents, personal data requiring content confidentiality.

### 13.2 Blob Chunk Keys

For each chunk of a blob:

```
chunk_id    = BLAKE3(chunk_plaintext)
chunk_key   = HKDF(blob_key, salt=chunk_id, info="lux/v1/chunk-key", L=32)
chunk_nonce = HKDF(blob_key, salt=chunk_id, info="lux/v1/chunk-nonce", L=24)
aad         = BlobId || ChunkId
```

---

## 14. Resilience Protocol

### 14.1 Redundancy Model

Users specify redundancy requirements per object:

```rust
struct ResiliencePolicy {
    min_replicas: u8,      // Minimum concurrent holders
    lease_ttl: Duration,   // Lease duration before renewal
    repair_threshold: u8,  // Trigger repair when replicas fall below
}
```

### 14.2 Health Monitoring

Clients (or delegated custodians) periodically verify redundancy:

1. Query DHT for `ChunkHolders` records
2. Count distinct, non-expired holders
3. If count < `repair_threshold`, initiate repair

### 14.3 Repair Procedure

```
1. Identify under-replicated chunks
2. Retrieve chunk from existing holder
3. Select new storage node (disjoint from current holders)
4. Upload chunk to new node
5. Issue new StorageLease with appropriate TTL
6. Announce via DHT
```

### 14.4 Lease Renewal

Before lease expiration, clients MUST renew:

1. Generate new `StorageLease` with extended `expires_at`
2. Obtain holder countersignature
3. Announce updated lease via DHT

Failure to renew permits storage nodes to garbage-collect the data.

---

## 15. Test Vectors

### 15.1 HKDF-SHA-256

**RFC 5869 Test Case 1:**

```
IKM:  0x0b × 22
Salt: 000102030405060708090a0b0c
Info: f0f1f2f3f4f5f6f7f8f9
L:    42

OKM:  3cb25f25faacd57a90434f64d0362f2a
      2d2d0a90cf1a5a4c5db02d56ecc4c5bf
      34007208d5b887185865
```

**Network MAC Key:**

```
NetworkKey: 0x42 × 32
Info:       "lux/v1/network-mac"

Output:     23c6878c5619c870f4f1942e7e99897c
            d08ac69dd3276c575e6a7eac37a2cbdf
```

**Chunk Key Derivation:**

```
CapabilitySecret: 0xAA × 32
ObjectId:         0xBB × 32
ChunkId:          0xCC × 32

chunk_key_base:   532909a10b9188e1835d34a39a4f4ec6
                  929b761934fd5d06418d45d5c60299e5

chunk_key:        05410a674aa6224ead714901fad1b186
                  0916d4f4ca0eb14224ca9600ff8ee93e

chunk_nonce:      a2e10e6c62894bd744395bdd
                  258b73367ac18e4442537545
```

### 15.2 Canonical Encoding

| Value | Encoding |
|-------|----------|
| `Timestamp(1700000000000)` | `00 68 E5 CF 8B 01 00 00` |
| `CryptoVersion::V1` | `01 00 00 00` |
| `Vec<u8> [0xAA, 0xBB, 0xCC]` | `03 00 00 00 AA BB CC` |
| `Option::<u32>::None` | `00` |
| `Option::<u32>::Some(0x12345678)` | `01 78 56 34 12` |

---

## 16. Configuration

### 16.1 Default Parameters

```toml
[protocol]
version_major = 1
version_minor = 0

[crypto]
crypto_version = 1

[time]
max_clock_skew_ms = 300000

[chunking]
min_size = 65536
max_size = 1048576
mask_s_bits = 19
mask_l_bits = 17

[dht]
k = 20
alpha = 3
max_record_size = 65536
max_chunk_holders = 64

[resilience]
default_min_replicas = 3
default_lease_ttl_days = 7
repair_check_interval_hours = 1

[cache]
max_memory_mb = 256
max_disk_gb = 10
```

---

## 17. Invariants

### 17.1 Cryptographic Invariants

| Invariant | Consequence of Violation |
|-----------|-------------------------|
| RevisionId strictly monotonic per ObjectId | AEAD nonce reuse |
| CryptoVersion embedded in signed manifest | Offline decryption failure |
| AAD formats frozen per CryptoVersion | AEAD domain separation failure |
| CiphertextHash = BLAKE3(nonce ‖ ct ‖ tag) | Storage addressing failure |

### 17.2 Encoding Invariants

| Invariant | Consequence of Violation |
|-----------|-------------------------|
| Payloaded enums: tag ‖ payload | Cross-implementation signature failure |
| Maps sorted by encoded key bytes | Determinism failure |
| Encoded-key collisions rejected | Ambiguous encoding |

### 17.3 DHT Invariants

| Invariant | Consequence of Violation |
|-----------|-------------------------|
| MAC gate precedes all operations | Unauthenticated state acceptance |
| Holder merge is CRDT | Partition divergence |
| holder_key == lease.body.holder | State inconsistency |

---

## 18. Project Structure

The reference implementation is organized as a Rust workspace with the following crate structure:

```
lux/
├── Cargo.toml                  # Workspace definition
├── bin/
│   ├── lux/                    # CLI tool
│   │   └── src/main.rs
│   └── luxd/                   # Daemon service
│       └── src/main.rs
├── crates/
│   ├── lux-core/               # Core types, traits, and primitives
│   │   ├── src/
│   │   │   ├── # HKDF, AEAD, BLAKE3 wrappers
│   │   │   ├── # Canonical encoding implementation
│   │   │   ├── # NodeId, ObjectId, ChunkId types
│   │   │   └── # Timestamp and skew logic
│   │
│   ├── lux-proto/              # Wire protocol and message definitions
│   │   ├── src/
│   │   │   ├── # DHT record types
│   │   │   ├── # Storage lease types
│   │   │   └── # Message framing
│   │
│   ├── lux-dht/                # Kademlia implementation
│   │   ├── src/
│   │   │   ├── # Routing table logic
│   │   │   ├── # Record storage and merge logic
│   │   │   └── # DHT service actor
│   │
│   ├── lux-store/              # Local storage engine
│   │   ├── src/
│   │   │   ├── # ChunkStore implementation
│   │   │   ├── # BlobStore implementation
│   │   │   └── # RocksDB/Sled bindings
│   │
│   ├── lux-net/                # Network transport layer
│   │   ├── src/
│   │   │   ├── # Transport trait
│   │   │   ├── # Noise protocol handshake
│   │   │   └── # QUIC implementation
│   │
│   ├── lux-fs/                 # Filesystem integration
│   │   ├── src/
│   │   │   ├── # FUSE bindings
│   │   │   └── # Virtual filesystem logic
│   │
│   └── lux-cdc/                # Content-Defined Chunking
│       ├── src/
│       │   ├── # FastCDC algorithm
│       │   └── # Gear table generation
```

---

## Appendix A: Record Size Bounds

### ChunkAnnouncement Size

| Field | Bytes |
|-------|-------|
| locator.chunk_id | 32 |
| locator.ciphertext_hash | 32 |
| commitment.merkle_root | 32 |
| commitment.size | 8 |
| commitment.block_size | 4 |
| commitment.block_count | 4 |
| holder | 32 |
| issuer | 32 |
| issued_at | 8 |
| expires_at | 8 |
| issuer_signature | 64 |
| holder_signature | 64 |
| **Total** | **320** |

### ChunkHoldersValue Maximum Size

```
4 (length prefix) + 64 × (32 + 320) = 22,532 bytes < 65,536 ✓
```

---

## Appendix B: Assumption Register

| ID | Assumption | Validation |
|----|------------|------------|
| A1 | BLAKE3 anchors match default hash mode | Cross-implementation verification |
| A2 | Ed25519 rejects non-canonical signatures | Malleability test suite |
| A3 | Canonical encoding is injective for map keys | Collision detection test |
| A4 | Clock skew bounded by MAX_CLOCK_SKEW | Skew injection testing |

---

## Appendix C: References

| Document | Reference |
|----------|-----------|
| HKDF | RFC 5869 |
| HMAC | RFC 2104 |
| SHA-256 | FIPS 180-4 |
| Ed25519 | RFC 8032 |
| X25519 | RFC 7748 |
| ChaCha20-Poly1305 | RFC 8439 |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03 |
| BLAKE3 | github.com/BLAKE3-team/BLAKE3-specs @ 225d294 |
| FastCDC | Xia et al., USENIX ATC 2016 |
| Kademlia | Maymounkov & Mazières, IPTPS 2002 |
| Noise Protocol | noiseprotocol.org/noise.html |
| QUIC | RFC 9000 |
| Conformance Keywords | RFC 2119, RFC 8174 |
| Base64url | RFC 4648 §5 |