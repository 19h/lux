<h1 align="center">lux</h1>

<img width="1536" height="476" alt="lux" src="https://github.com/user-attachments/assets/9c1de266-1f5c-427f-a536-e50fc45e2c1b" />

---

<h5 align="center">
lux is a decentralized filesystem that presents a global encrypted mesh as a local mountpoint.<br/>
Files are content-addressed, deduplicated across the network, and fetched on demand at chunk granularity.<br/>
Open a 50GB file and only the bytes you actually read hit the wire.<br/>
<br/>
Storage nodes hold encrypted chunks with zero knowledge of content, filenames, or ownership.<br/>
The URI <i>is</i> the capability: possessing it grants read access.<br/>
Lacking it renders the data mathematically invisible.
</h5>

---

## Building

Requires Rust 1.70+, RocksDB dev libs, FUSE dev libs.

```bash
cargo build --release
cargo test --workspace  # 369 tests
```

## Usage

```bash
lux keygen                              # generate node identity
lux init ~/lux-data                     # initialize storage dir
luxd --config ~/.lux/config.toml        # start daemon

lux put myfile.txt                      # → lux:blob:af1349b9f5f9a1a6...
lux get lux:blob:af1349b9f5f9a1a6... out.txt
lux mount lux:blob:<id> /mnt/lux
```

Mounting exposes standard POSIX semantics. Applications read/write normally; Lux intercepts syscalls via FUSE, translates byte ranges to chunk fetches, decrypts in memory, and returns plaintext to the kernel. Local RocksDB cache ensures repeated reads hit disk, not network.

## URI Schemes

**Immutable blobs**: `lux:blob:<base64url(BLAKE3(plaintext))>`

Content-addressed. Convergent encryption means identical files produce identical ciphertext network-wide → global deduplication. Tradeoff: vulnerable to confirmation attacks (attacker with candidate plaintext can verify you have it).

**Mutable objects**: `lux:obj:<ObjectId>:<CapabilitySecret>[:<RevisionId>]`

Versioned, signed by origin's Ed25519 key. Append RevisionId for point-in-time access. Random CapabilitySecret means no deduplication but actual confidentiality.

## Data Model

Files are split via FastCDC (content-defined chunking) into 64K–1M chunks. CDC finds mathematical breakpoints in the byte stream rather than fixed offsets, so inserting data at the start of a file only invalidates the affected chunk. The rest deduplicate against the original.

Chunks form a Merkle DAG: leaves hold encrypted data, intermediate nodes hold chunk lists, root manifest describes the full tree. Changing any byte cascades hash changes up to the root, so a root hash uniquely identifies exact file state. Revisions are cheap. Editing 1MB in a 10GB file stores only ~1MB of new chunks.

## Storage Model

Storage is contractual. Uploading chunks to remote nodes requires issuing a **Storage Lease**, a signed authorization with TTL. Nodes garbage-collect unleased chunks. To maintain redundancy:

1. Client (or custodian node) monitors DHT for replica count
2. If nodes vanish and replicas drop below threshold, repair triggers
3. Surviving replica is fetched, re-uploaded to fresh node, new lease issued

This is the "resilience promise": request N replicas, network autonomously maintains N replicas until you stop renewing leases.

## Architecture

```
lux-core    Crypto primitives, identifiers, canonical encoding
lux-cdc     FastCDC chunking (64K min / 256K avg / 1M max)
lux-proto   Wire formats, DHT records, manifests, leases
lux-store   RocksDB persistence layer
lux-dht     Kademlia (k=20, α=3) with CRDT merge
lux-net     Noise NK over QUIC, TCP fallback
lux-fs      FUSE interface
lux-tests   Integration tests
```

## Cryptography

| | |
|-|-|
| KDF | HKDF-SHA-256 (RFC 5869) |
| MAC | HMAC-SHA-256 (RFC 2104) |
| AEAD | XChaCha20-Poly1305 |
| Hash | BLAKE3-256 |
| Signatures | Ed25519 pure (RFC 8032) |
| Key agreement | X25519 (RFC 7748) |

## Network Stack

```
Lux Protocol Messages
        ↓
   Noise NK
        ↓
 QUIC / TCP fallback
        ↓
 UDP / TCP / WebSocket
```

DHT (Kademlia, k=20, α=3) maps content hashes to node addresses. Query "who has chunk X" → get peer list → fetch directly.

Nodes form a mesh. If A can't reach B directly (NAT, firewall), traffic routes through C. C sees only Noise ciphertext. WebSocket transport available for hostile networks that block UDP/raw TCP—looks like standard HTTPS.

## Configuration

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

[dht]
k = 20
alpha = 3
max_record_size = 65536
max_chunk_holders = 64

[resilience]
default_min_replicas = 3
default_lease_ttl_days = 7
```

## Security Notes

Storage nodes see only ciphertext. Convergent encryption enables deduplication but is vulnerable to confirmation attacks—if an attacker can guess your plaintext, they can verify possession. Use object URIs with random capability secrets for confidential data.

## Status

Core implementation complete: chunking, encryption, DHT, storage, FUSE mount, versioning all work.

**Not yet implemented:**
- NAT traversal (STUN/TURN hole-punching)—currently requires at least one publicly-reachable node
- Relay fallback for fully symmetric NAT situations  
- Automated health monitoring daemon (manual repair works, autonomous repair doesn't)

See [SPECIFICATION.md](SPECIFICATION.md) for protocol details.
