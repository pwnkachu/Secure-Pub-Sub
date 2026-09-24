# Rust reference implementation

This workspace follows the protocol definition in [`../../protocol/README.md`](../../protocol/README.md).
Read it from the core outward:

1. `crates/protocol-core`: allocation-free wire encoding, predicates and cryptography.
2. `crates/agent-core`: request construction and delivery validation.
3. `crates/ca-core`: authorization, matching, replay state and persistent storage.
4. `crates/transport`: bounded Tokio TCP framing for the CA, broker and desktop Agents.
5. `crates/embassy-transport`: `no_std`, allocation-free framing and clock for Embassy Agents.
6. `crates/broker-core` and `crates/usecase-models`: routing and typed application schemas.
7. `apps`: runnable Tokio processes plus the Embassy smart-building sensor component.

The root [`README`](../../README.md) contains the complete build, test, provisioning and launch
commands for all three examples. Security and deployment assumptions are documented in
[`SECURITY.md`](SECURITY.md).
