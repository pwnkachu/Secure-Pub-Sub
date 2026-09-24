# SecurePubSub

SecurePubSub is a bounded, secure publish/subscribe protocol in which a trusted Certificate
Authority (CA) authenticates agents, evaluates predicates and authorization policy, and creates an
independently protected delivery for every subscriber. The broker only routes opaque envelopes.

This repository is intentionally organized as a short learning path:

1. Read the protocol definition in [`protocol/README.md`](protocol/README.md).
2. Follow the three historical Tamarin models in [`protocol/formal-v1`](protocol/formal-v1), then
   the final model in [`protocol/formal-v2`](protocol/formal-v2).
3. Read the allocation-free wire and cryptographic core in
   [`implementations/rust/crates/protocol-core`](implementations/rust/crates/protocol-core).
4. Continue with the agent, CA, broker and transport crates, then run one of the application
   examples under [`implementations/rust/apps`](implementations/rust/apps).

The `formal-v1` and `formal-v2` names describe iterations of the symbolic model. The implemented
wire format is still identified as `SecurePubSub/v1`.

## Repository layout

```text
protocol/
  README.md                 protocol roles, operations and security boundary
  formal-v1/                basic -> replay-safe -> authenticated-delivery models
  formal-v2/                final Tamarin model used by the Rust implementation
implementations/
  rust/
    crates/                 protocol, agent, CA, broker, authenticated link, transport and use-case libraries
    apps/                   broker, CA, Tokio Agents and an Embassy sensor Agent
    config/examples/        complete example policy and process configurations
```

Generated keys, state, build output, editor settings, benchmarks and fuzzing corpora are not part
of the archived source tree.

## Build and test the Rust implementation

Requirements: Rust 1.91 or newer and Cargo. From the repository root:

```bash
cd implementations/rust
cargo build --workspace --locked
cargo test --workspace --all-features --locked
cargo check -p protocol-core --no-default-features --locked
cargo check -p agent-core --no-default-features --locked
cargo check -p embassy-transport --lib --locked
cargo check -p smart-building-embassy-agent --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

`cargo test` covers the protocol codecs and cryptography, CA policy and persistence, in-memory
end-to-end flows, and real TCP process integration. To run only the process-level suite:

```bash
cargo test -p cad --test tcp_processes -- --nocapture
```

## Run the Rust examples

All commands below run from `implementations/rust`. Build once, then create independent CA and
agent key pairs. The key generator refuses to overwrite existing files.

```bash
cargo build --workspace --locked
mkdir -p secrets state
openssl rand -hex 32 > secrets/broker-ca.psk
./target/debug/secure-pubsub-keygen --kind ca --output secrets
for agent in building-sensor building-panel building-maintenance \
             scout coordinator responder tenant-publisher tenant-consumer; do
  ./target/debug/secure-pubsub-keygen \
    --kind agent --prefix "$agent" --output secrets
done
```

Start the CA listener first, then the broker that owns and maintains the
infrastructure connection to it:

```bash
# terminal 1
./target/debug/cad --config config/examples/ca.json

# terminal 2
./target/debug/brokerd --listen 127.0.0.1:7400 --ca 127.0.0.1:7500 \
  --ca-psk-file secrets/broker-ca.psk
```

`cad` services one broker connection at a time; another connection can wait in
the operating-system backlog but is not accepted until the active broker link
closes. Before accepting that connection as infrastructure, `cad` sends a random
challenge and verifies an HMAC-SHA256 response under the configured 32-byte PSK.
Authentication has a deadline; established links have no inactivity timeout.
The broker reconnects with bounded exponential backoff and never puts
this infrastructure link in the public Agent connection map. In particular,
an Agent hello containing the reserved CA identity is rejected.

The Broker--CA link wraps each unchanged SecurePubSub envelope in a small
length-delimited internal `Request` or `Delivery` frame with a random identifier.
The receiver sends `Ack` only after acquiring the item in bounded local state.
Every unacknowledged item is retained and retransmitted on a timer and after
reconnection; bounded deduplication suppresses link-level duplicates. Requests
are serialized. For a publication, the CA does not acknowledge the request until
the broker has acknowledged every generated delivery. This is at-least-once
across TCP link failures within the lifetime of both processes, not exactly-once.
The CA's temporary link state is not yet durable, so a CA process crash between
consuming a one-shot and the broker ACK remains a documented loss window.

Agent connections are on demand. Disconnecting does not remove environments or
subscriptions persisted by the CA. Deliveries for disconnected Agents are kept
in bounded, in-memory FIFO queues and are sent after the next hello. Queues do
not survive a broker restart; a full online, offline, or CA queue fails closed
and produces a `QueueFull` log event rather than silently growing or dropping.
Use `brokerd --help` for the independent handshake, Agent I/O, CA connect and
CA reconnect limits and for online/offline queue capacities. The default
deployment has no transport heartbeat.

Publisher roles use `connect -> hello -> environment + publication -> close`
for each later publication, preserving request order without an idle socket.
Subscribers keep a socket only while waiting. Reconnection of a
one-shot wait does not register another subscription; stable
`(subscriber, type, handler)` keys also make replacement idempotent at the CA.
The public Broker--Agent delivery path remains explicitly best-effort after a
successful TCP write: a failed write is requeued, but there is no Agent ACK after
validation. Agent replay caches reject duplicate authenticated `SessionId`s.

Then choose one implementation below and run each command in its own terminal.

### Smart building

```bash
./target/debug/smart-building-agent --config config/examples/smart-building-control-panel.json
./target/debug/smart-building-agent --config config/examples/smart-building-maintenance.json
printf '2150\n2210\n' | ./target/debug/smart-building-agent \
  --config config/examples/smart-building-sensor.json
```

The sensor publishes temperature readings; the control panel and maintenance terminal keep
subscriptions constrained to their configured building and roles.

#### Embedded sensor with Embassy

`smart-building-embassy-agent` implements the same sensor role without `std` or heap allocation.
It uses `embassy-transport`, which implements `protocol_core::AsyncTransport` over any
`embedded_io_async::Read + Write` stream. `embassy_net::tcp::TcpSocket` satisfies that contract, so
the embedded sensor communicates directly with the unchanged Tokio broker and CA.

Board firmware is responsible for starting the Embassy network runner, connecting a TCP socket to
port 7400, loading provisioned keys and seeding a cryptographic RNG from hardware entropy. It then
wraps the connected socket and drives the use-case component:

```rust,ignore
let mut rx = [0u8; 1024];
let mut tx = [0u8; 1024];
let mut socket = embassy_net::tcp::TcpSocket::new(stack, &mut rx, &mut tx);
socket.connect((broker_address, 7400)).await?;

let mut transport = embassy_transport::EmbassyFramedTransport::with_timeout(
    socket,
    embassy_time::Duration::from_secs(10),
);
let sensor = smart_building_embassy_agent::EmbassySensorAgent::new(agent, sensor_config);
let mut frame = [0u8; protocol_core::MAX_FRAME_LEN];

sensor.initialize(&mut transport, &mut hardware_seeded_rng, &mut frame).await?;
loop {
    let reading = read_temperature_sensor().await;
    sensor
        .publish_temperature(reading, &mut transport, &mut hardware_seeded_rng, &mut frame)
        .await?;
}
```

The frame buffer is reused for every operation. Socket buffers may be smaller because TCP reads
and writes are handled incrementally. After a timeout or I/O error, discard the adapter, create a
fresh socket and transport, and call `initialize` again; a cancelled partial framed write is not
recoverable safely. This remains board-firmware policy and requires neither Tokio nor heap
allocation.

### Robot swarm

```bash
./target/debug/robot-swarm-agent --config config/examples/swarm-coordinator.json
./target/debug/robot-swarm-agent --config config/examples/swarm-responder.json
printf 'battery=90\ntarget thermal-contact\n' | ./target/debug/robot-swarm-agent \
  --config config/examples/swarm-scout.json
```

The coordinator accepts `<responder-agent-id-hex> <task>` on standard input. This example models
mission messaging and telemetry, not hard-real-time flight control.

### Multi-tenant messaging

```bash
./target/debug/multi-tenant-agent --config config/examples/tenant-consumer.json
printf 'order.created\n' | ./target/debug/multi-tenant-agent \
  --config config/examples/tenant-publisher.json
```

The application builders and CA policy both enforce the tenant boundary.

## Check the formal models

Install Tamarin Prover and first parse every model:

```bash
for model in protocol/formal-v1/*.spthy protocol/formal-v2/*.spthy; do
  tamarin-prover --parse-only "$model" >/dev/null
done
```

Run the recorded executability proof, or ask Tamarin to attempt every stated property, with:

```bash
tamarin-prover --prove=Executability_Receive_Publication \
  protocol/formal-v2/SecurePubSubV2.spthy
tamarin-prover --prove protocol/formal-v2/SecurePubSubV2.spthy
```

Only the executability lemma has a recorded automatic proof in the archived model. Other property
statements may report `analysis incomplete`; they are retained as the explicit verification scope,
not presented as completed proofs. A complete proof attempt can take substantially longer than
parsing or the focused lemma.

## Scope and security

The CA is trusted and sees plaintext environments and publications while matching. The broker
does not. Transport authentication, distributed CA operation, HSM integration and board-specific
device drivers remain deployment concerns outside this reference repository. See
[`implementations/rust/SECURITY.md`](implementations/rust/SECURITY.md) for the threat boundary,
key-management rules and operational limits.
