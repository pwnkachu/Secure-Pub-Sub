# Protocol core

SecurePubSub has three roles:

- **Agent**: owns an environment, subscribes to typed publications and/or publishes a value.
- **Certificate Authority (CA)**: authenticates agents, enforces environment policy, stores
  subscriptions, evaluates predicates and protects deliveries.
- **Broker**: forwards bounded opaque frames between identities without decrypting them.

## Operations

An agent sends one of four requests to the CA:

1. `SetEnvironment` replaces its bounded typed attribute set.
2. `Subscribe` registers a one-shot `(type, predicate, handler)` subscription.
3. `SubscribePermanent` registers a persistent subscription of the same form.
4. `Publish` submits `(type, audience predicate, value)`.

For a publication, the CA authenticates and decrypts the request, checks replay and authorization,
and finds subscriptions where both predicates hold: the publication audience matches the
subscriber environment and the subscription predicate matches the publisher environment. It then
creates a `PublicationResponse` encrypted and signed for each matching subscriber.

```text
Agent -- signed, encrypted request --> Broker -- opaque frame --> CA
CA -- authenticate / replay-check / authorize / match
CA -- separately protected delivery --> Broker -- opaque frame --> Agent
```

Predicates are bounded conjunctions over Boolean, signed-integer and byte-string attributes. The
wire core limits environments to 16 attributes, predicates to 8 clauses, attribute byte strings to
64 bytes, publication values to 3072 bytes and plaintext operations to 4096 bytes.

## Cryptographic envelope

Each message uses a fresh ephemeral-static X25519 exchange, HKDF-SHA256,
ChaCha20-Poly1305 and an Ed25519 signature. The KDF and signed transcript bind the protocol,
version, direction, message purpose, sender, recipient, session, ephemeral key and ciphertext.
Replay identity is the authenticated sender plus a random 128-bit session identifier.

This is a project-specific authenticated hybrid construction; it does not claim compatibility
with standard ECIES or HPKE. The CA is a trusted confidentiality and authorization component.

## Formal development path

The models are ordered so that each directory can be studied without reading implementation code:

- [`formal-v1/01-basic.spthy`](formal-v1/01-basic.spthy): initial authenticated protocol.
- [`formal-v1/02-replay-protection.spthy`](formal-v1/02-replay-protection.spthy): introduces nonce
  checking to address replay.
- [`formal-v1/03-authenticated-delivery.spthy`](formal-v1/03-authenticated-delivery.spthy): adds CA
  authentication of deliveries and type-confusion coverage.
- [`formal-v2/SecurePubSubV2.spthy`](formal-v2/SecurePubSubV2.spthy): final tractable model using
  one-message X25519 sessions and the security properties implemented by the Rust reference.

The V2 model treats X25519 as a private idealized KEM. Its four receive rules use Tamarin's
`no_derivcheck` annotation because the receiver's static-secret ownership is present in the rule
but intentionally absent from the public-key-only `x25519_ss` abstraction. The annotation and its
rationale are recorded beside the function declaration in the model.

Model-directory versions record the evolution of the formalization; they are not wire-version
numbers. The Rust wire protocol is `SecurePubSub/v1`.
