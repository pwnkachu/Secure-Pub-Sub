# Embassy smart-building sensor

This `no_std` library is the embedded counterpart of the Tokio smart-building sensor. It builds
the same typed environment and publication audience, but sends them through
`embassy_transport::EmbassyFramedTransport` using one caller-owned protocol buffer.

The crate deliberately contains no board-specific binary. A firmware target must provide:

- an initialized Embassy executor, time driver and `embassy-net` runner;
- a connected `embassy_net::tcp::TcpSocket`;
- provisioned Agent and CA keys;
- a `rand_core::CryptoRng` seeded from hardware entropy;
- a temperature driver and a reusable `[u8; protocol_core::MAX_FRAME_LEN]` buffer.

Call `EmbassySensorAgent::initialize` once per connection, then
`EmbassySensorAgent::publish_temperature` for each reading. CA and Broker remain the existing Tokio
processes; framing and cryptographic envelopes are identical on both transports. After an I/O or
timeout error, board firmware drops the socket and transport, creates a fresh pair, and calls
`initialize` again to resend the hello and current environment. No allocator is required.
