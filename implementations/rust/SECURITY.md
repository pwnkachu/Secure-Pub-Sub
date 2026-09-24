# Security policy and operations

## Cryptographic construction and trusted boundary

The protocol uses an authenticated ECIES-like hybrid encryption construction based on
ephemeral-static X25519, HKDF-SHA256, ChaCha20-Poly1305, and Ed25519 signatures. It does not claim
compatibility with standard ECIES or HPKE. The CA authenticates and decrypts requests, sees
plaintext payloads and environments, evaluates policy and predicates, and re-encrypts each
delivery. The CA is therefore a trusted confidentiality and authorization component.

## Key management and provisioning

Generate Ed25519 and X25519 keys independently from an OS CSPRNG. Never derive one from the other.
Agent public key pairs must reach the CA over an authenticated administrative channel.
Deterministic seeds exist only in tests and are rejected as a production practice.

Embedded Agents must seed their `CryptoRandom` implementation from a hardware entropy source
before constructing any envelope. Provisioned Ed25519 and X25519 secrets must live in protected
flash or a secure element when the target provides one. The Embassy adapter does not allocate or
copy complete frames internally, but plaintext and key material still reside in caller-owned RAM.
Clear or reuse those buffers deliberately according to the device threat model.

Attributes used to grant authorization must be approved by the CA. Identity, building, tenant,
swarm, mission epoch, role, clearance, certification, and capability claims must never be accepted
as self-declared values. `StaticEnvironmentPolicy` binds these values to authenticated identities;
`AllowAllEnvironmentPolicy` is a compatibility facility and is unsuitable for new deployments.

`cad` reads private material from explicit files and never from command-line values visible in
process listings. A hardened deployment should replace files with a secrets-manager/HSM adapter.
Restrict core dumps, swap, ptrace, and snapshot access. The snapshot is mode `0600` on
Unix and atomically replaced after `fsync`; it contains plaintext environments and subscriptions,
public keys, and replay identifiers, but never CA private keys. Use an encrypted filesystem.

Dalek secret types, AEAD key state, and `Zeroizing` derived key/nonce/shared-secret buffers wipe on
drop. Compiler-enforced consuming `EphemeralSecret` prevents protocol-level reuse. Zeroization
cannot guarantee removal of register copies, prior heap reallocations, swap, or crash dumps.

## Replay, rotation, and recovery

Replay identity is `(authenticated sender, random 128-bit session_id)`, not a timestamp. Entries
expire after a configurable TTL. Expired entries are removed in deterministic key order;
unexpired capacity exhaustion fails closed. CA persistent state includes replay entries so a clean
restart does not reopen the replay window. Agent replay state is supplied by the application; a
production Agent must persist it if restart replay is unacceptable.

Key rotation is an authenticated provisioning transaction. Because envelopes contain no key ID,
coordinate rotation: stop accepting new traffic, drain bounded queues, replace directory and
local keys, then restart. A future version should add signed key epochs for overlap without wire
ambiguity. Never reuse snapshots across trust domains. Configuration reload reconciles the Agent
directory atomically; removal or rotation also removes that identity's environment, subscriptions,
and replay entries. Delivery revalidates stored environments under one policy snapshot.

## Operational limits

- Plaintext/encrypted operation: 4096 bytes; publication value: 3072 bytes.
- Environment: 16 attributes; predicate: 8 clauses; attribute bytes: 64.
- Defaults: 1024 Agents/environments, 4096 subscriptions, 16384 replay entries, 600-second TTL.
- Broker defaults: 1024 connected Agent identities, 1024 concurrent pending handshakes, 64 online
  frames and 64 offline frames per identity, plus 256 Agent requests waiting for the dedicated CA
  link. Offline queues are memory only and are lost on broker restart. Capacity exhaustion is
  logged as `QueueFull` and fails closed.

The 16-byte TCP hello is untrusted routing metadata, not authentication. The broker still requires
every envelope sender to match the socket's declared identity; Ed25519 signatures and CA protocol
validation authenticate messages. The public Agent listener rejects the reserved CA identity. The
separate Broker--CA socket uses a random challenge and HMAC-SHA256 under a deployment PSK before it
becomes persistent. Authentication has a timeout; the authenticated connection has no inactivity
timeout or SecurePubSub heartbeat. The secret is read from a file and is never logged. In the
current deployment `cad` accepts and services one authenticated broker connection at a time. Use a
unique randomly generated PSK with file-system protections; mTLS remains the recommended future
replacement for peer identity, confidentiality, and operational key rotation.
Changing the PSK path or value requires restarting both infrastructure processes;
policy hot reload deliberately does not rotate transport credentials.

The internal infrastructure protocol provides bounded at-least-once transfer across Broker--CA TCP
disconnects: opaque envelopes have random link IDs, remain pending until acquisition ACK, and are
deduplicated on retransmission. Publication requests are not acknowledged until every generated
delivery is acquired by the broker. Pending and dedup state is in process memory. A broker restart
loses offline Agent queues; a CA restart can lose unacknowledged link deliveries after a one-shot
was durably consumed. Consequently the implementation does not claim end-to-end exactly-once.
The public Broker--Agent path is best-effort after a successful TCP write because Agents do not send
a post-validation delivery ACK. Failed writes are requeued; successful kernel writes are not.

Capacity and cryptographic failures reveal no plaintext or secret. Operators should log aggregate
counts and error classes only. Do not add debug formatting for key-bearing structs or log decrypted
buffers.

## Limitations and future hardening

`broker-core::OfflineQueueStore` isolates offline delivery storage from routing; the reference
`MemoryOfflineQueueStore` is bounded and intentionally non-durable so a future persistent adapter
can be added without changing routing semantics.

The file adapter rewrites a bounded snapshot on every mutation; it is crash-consistent but intended
for demos/small installations, not high-write multi-node CA service. Use a transactional database
with equivalent trait semantics and rollback protection at scale. Add authenticated transport
(mTLS), isolated key storage/HSM integration, rate limiting by authenticated peer, and formal
equivalence checks between byte-level Rust traces and Tamarin facts before Internet exposure.

No third-party security audit has been performed. Cryptographic dependencies are maintained
Dalek/RustCrypto implementations, but composition and application code still require independent
review.
