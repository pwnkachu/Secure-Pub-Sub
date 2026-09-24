#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Stateful, allocation-free Agent facade over the portable protocol core.
//!
//! The optional `alloc` feature only adds convenience methods returning `Vec<u8>` for desktop
//! adapters. The default API writes into caller-owned bounded buffers and can be driven by any
//! `no_std` async executor, including Embassy.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};
use core::fmt;
#[cfg(feature = "alloc")]
use protocol_core::{AttributeId, EnvironmentRef, ValueRef};

use ed25519_dalek::{SigningKey, VerifyingKey};
use protocol_core::{
    AgentId, AsyncTransport, AttributeRef, ClauseRef, Clock, CryptoRandom, Error, HEADER_LEN,
    HandlerId, MAX_FRAME_LEN, MessageType, OneShotSecret, OperationRef, ReplayProtector, SessionId,
    TypeId, encode_environment, encode_publish, encode_subscribe, encode_subscribe_permanent,
    open_in_place, parse_envelope, parse_operation, seal_in_place, verify_envelope_signature,
};
use x25519_dalek::StaticSecret;

/// Callback invoked for every authenticated publication of a permanent subscription.
///
/// The delivery borrows the reusable receive buffer and therefore cannot be retained. An
/// application that needs the value later must copy it into its own bounded static storage.
pub trait SubscriptionHandler {
    /// Handles one matching, authenticated publication.
    fn on_publication(&mut self, delivery: Delivery<'_>);
}

impl<F> SubscriptionHandler for F
where
    F: for<'a> FnMut(Delivery<'a>),
{
    fn on_publication(&mut self, delivery: Delivery<'_>) {
        self(delivery);
    }
}

/// Failure returned by an asynchronous subscription operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionError<E> {
    /// Envelope construction, authentication, replay, or payload validation failed.
    Protocol(Error),
    /// Sending or receiving failed in the platform transport.
    Transport(E),
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    sender: AgentId,
    session: SessionId,
    expires_at: u64,
}

/// Fixed-capacity, allocation-free replay protector for embedded Agents.
///
/// Expired entries are reclaimed before insertion. An unexpired full cache fails closed.
pub struct FixedReplayCache<const N: usize> {
    entries: [Option<ReplayEntry>; N],
    ttl_seconds: u64,
}

impl<const N: usize> FixedReplayCache<N> {
    /// Creates an empty cache with the given replay time-to-live.
    pub const fn new(ttl_seconds: u64) -> Self {
        Self {
            entries: [None; N],
            ttl_seconds,
        }
    }

    /// Number of currently occupied entries, including entries not yet lazily expired.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    /// Whether the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<const N: usize> ReplayProtector for FixedReplayCache<N> {
    fn check_and_mark(
        &mut self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error> {
        for entry in &mut self.entries {
            if entry.is_some_and(|entry| entry.expires_at <= now_seconds) {
                *entry = None;
            }
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.sender == sender && entry.session == session)
        {
            return Err(Error::Replay);
        }
        let vacant = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::Capacity)?;
        *vacant = Some(ReplayEntry {
            sender,
            session,
            expires_at: now_seconds.saturating_add(self.ttl_seconds),
        });
        Ok(())
    }
}

impl<E: fmt::Display> fmt::Display for SubscriptionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "subscription protocol failure: {error}"),
            Self::Transport(error) => {
                write!(formatter, "subscription transport failure: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for SubscriptionError<E> where E: std::error::Error + 'static {}

/// Long-term Agent keys. Ed25519 and X25519 material are deliberately separate.
pub struct AgentKeys {
    signing: SigningKey,
    x25519: StaticSecret,
}

impl AgentKeys {
    /// Loads provisioned keys from two independent 32-byte secrets.
    pub fn from_seeds(ed25519_seed: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&ed25519_seed),
            x25519: StaticSecret::from(x25519_secret),
        }
    }

    /// Public Ed25519 verification key.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Public static X25519 key.
    pub fn x25519_public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.x25519).to_bytes()
    }
}

/// Public keys of the provisioned CA trust anchor.
#[derive(Clone, Copy)]
pub struct CaPublicKeys {
    /// Ed25519 verification key.
    pub ed25519: [u8; 32],
    /// Static X25519 public key.
    pub x25519: [u8; 32],
}

/// An Agent bound to one provisioned identity and CA.
pub struct Agent {
    id: AgentId,
    keys: AgentKeys,
    ca: CaPublicKeys,
}

impl Agent {
    /// Constructs a provisioned Agent.
    pub const fn new(id: AgentId, keys: AgentKeys, ca: CaPublicKeys) -> Self {
        Self { id, keys, ca }
    }

    /// Agent identity.
    pub const fn id(&self) -> AgentId {
        self.id
    }

    /// Public Ed25519 key for CA provisioning.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.keys.verifying_key()
    }

    /// Public X25519 key for CA provisioning.
    pub fn x25519_public(&self) -> [u8; 32] {
        self.keys.x25519_public()
    }

    /// Writes a signed, encrypted environment replacement request into `output`.
    pub fn set_environment_into(
        &self,
        output: &mut [u8],
        attributes: &[AttributeRef<'_>],
        rng: &mut impl CryptoRandom,
    ) -> Result<usize, Error> {
        self.request_into(
            output,
            MessageType::SetEnvironment,
            HandlerId::NONE,
            rng,
            |plain| encode_environment(plain, attributes),
        )
    }

    /// Writes a signed, encrypted one-shot subscription request into `output`.
    pub fn subscribe_into(
        &self,
        output: &mut [u8],
        type_id: TypeId,
        handler: HandlerId,
        predicate: &[ClauseRef<'_>],
        rng: &mut impl CryptoRandom,
    ) -> Result<usize, Error> {
        if handler == HandlerId::NONE {
            return Err(Error::WrongHandler);
        }
        self.request_into(output, MessageType::Subscribe, handler, rng, |plain| {
            encode_subscribe(plain, type_id, predicate)
        })
    }

    /// Writes a signed, encrypted permanent subscription request into `output`.
    ///
    /// The CA retains this subscription and uses the nonzero handler for every future matching
    /// delivery. Reusing `(agent, type, handler)` replaces the previous subscription atomically.
    pub fn subscribe_permanent_into(
        &self,
        output: &mut [u8],
        type_id: TypeId,
        handler: HandlerId,
        predicate: &[ClauseRef<'_>],
        rng: &mut impl CryptoRandom,
    ) -> Result<usize, Error> {
        if handler == HandlerId::NONE {
            return Err(Error::WrongHandler);
        }
        self.request_into(
            output,
            MessageType::SubscribePermanent,
            handler,
            rng,
            |plain| encode_subscribe_permanent(plain, type_id, predicate),
        )
    }

    /// Writes a signed, encrypted publication request into `output`.
    pub fn publish_into(
        &self,
        output: &mut [u8],
        type_id: TypeId,
        predicate: &[ClauseRef<'_>],
        value: &[u8],
        rng: &mut impl CryptoRandom,
    ) -> Result<usize, Error> {
        self.request_into(
            output,
            MessageType::Publish,
            HandlerId::NONE,
            rng,
            |plain| encode_publish(plain, type_id, predicate, value),
        )
    }

    /// Registers a subscription once, then invokes `handler_fn` for every matching delivery.
    ///
    /// Successful execution is intentionally infinite: it ends only when cancelled by the async
    /// executor or when transport/protocol validation fails. The same caller-owned frame is reused
    /// for the request and every response, so this method performs no heap allocation. A transport
    /// should be owned by only one such loop; multiplexing several subscriptions belongs in a
    /// higher-level dispatcher.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_permanent<T, R, C, H>(
        &self,
        type_id: TypeId,
        handler: HandlerId,
        predicate: &[ClauseRef<'_>],
        transport: &mut T,
        replay: &mut R,
        clock: &C,
        rng: &mut impl CryptoRandom,
        frame: &mut [u8],
        mut handler_fn: H,
    ) -> Result<(), SubscriptionError<T::Error>>
    where
        T: AsyncTransport,
        R: ReplayProtector,
        C: Clock,
        H: SubscriptionHandler,
    {
        let request_len = self
            .subscribe_permanent_into(frame, type_id, handler, predicate, rng)
            .map_err(SubscriptionError::Protocol)?;
        transport
            .send(&frame[..request_len])
            .await
            .map_err(SubscriptionError::Transport)?;

        loop {
            let frame_len = transport
                .receive(frame)
                .await
                .map_err(SubscriptionError::Transport)?;
            let received = frame
                .get_mut(..frame_len)
                .ok_or(SubscriptionError::Protocol(Error::Oversized))?;
            let delivery = self
                .receive(received, handler, replay, clock.now_seconds())
                .map_err(SubscriptionError::Protocol)?;
            if delivery.type_id != type_id {
                return Err(SubscriptionError::Protocol(Error::WrongMessageType));
            }
            handler_fn.on_publication(delivery);
        }
    }

    /// Registers a one-shot subscription and waits for its first matching delivery.
    ///
    /// The CA consumes the subscription atomically before producing the response, so another
    /// publication cannot match it again. The returned delivery borrows `frame`.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_once<'a, T, R, C>(
        &self,
        type_id: TypeId,
        handler: HandlerId,
        predicate: &[ClauseRef<'_>],
        transport: &mut T,
        replay: &mut R,
        clock: &C,
        rng: &mut impl CryptoRandom,
        frame: &'a mut [u8],
    ) -> Result<Delivery<'a>, SubscriptionError<T::Error>>
    where
        T: AsyncTransport,
        R: ReplayProtector,
        C: Clock,
    {
        let request_len = self
            .subscribe_into(frame, type_id, handler, predicate, rng)
            .map_err(SubscriptionError::Protocol)?;
        transport
            .send(&frame[..request_len])
            .await
            .map_err(SubscriptionError::Transport)?;
        let frame_len = transport
            .receive(frame)
            .await
            .map_err(SubscriptionError::Transport)?;
        let received = frame
            .get_mut(..frame_len)
            .ok_or(SubscriptionError::Protocol(Error::Oversized))?;
        let delivery = self
            .receive(received, handler, replay, clock.now_seconds())
            .map_err(SubscriptionError::Protocol)?;
        if delivery.type_id != type_id {
            return Err(SubscriptionError::Protocol(Error::WrongMessageType));
        }
        Ok(delivery)
    }

    /// Creates a signed, encrypted environment replacement request on the heap.
    #[cfg(feature = "alloc")]
    pub fn set_environment(
        &self,
        attributes: &[AttributeRef<'_>],
        rng: &mut impl CryptoRandom,
    ) -> Result<Vec<u8>, Error> {
        self.request_owned(|output| self.set_environment_into(output, attributes, rng))
    }

    /// Creates a signed, encrypted one-shot subscription request on the heap.
    #[cfg(feature = "alloc")]
    pub fn subscribe(
        &self,
        type_id: TypeId,
        handler: HandlerId,
        predicate: &[ClauseRef<'_>],
        rng: &mut impl CryptoRandom,
    ) -> Result<Vec<u8>, Error> {
        self.request_owned(|output| self.subscribe_into(output, type_id, handler, predicate, rng))
    }

    /// Creates a signed, encrypted permanent subscription request on the heap.
    #[cfg(feature = "alloc")]
    pub fn subscribe_permanent_request(
        &self,
        type_id: TypeId,
        handler: HandlerId,
        predicate: &[ClauseRef<'_>],
        rng: &mut impl CryptoRandom,
    ) -> Result<Vec<u8>, Error> {
        self.request_owned(|output| {
            self.subscribe_permanent_into(output, type_id, handler, predicate, rng)
        })
    }

    /// Creates a signed, encrypted publication request on the heap.
    #[cfg(feature = "alloc")]
    pub fn publish(
        &self,
        type_id: TypeId,
        predicate: &[ClauseRef<'_>],
        value: &[u8],
        rng: &mut impl CryptoRandom,
    ) -> Result<Vec<u8>, Error> {
        self.request_owned(|output| self.publish_into(output, type_id, predicate, value, rng))
    }

    /// Verifies replay/recipient/handler, decrypts, and parses one CA delivery.
    pub fn receive<'a>(
        &self,
        frame: &'a mut [u8],
        expected_handler: HandlerId,
        replay: &mut impl ReplayProtector,
        now_seconds: u64,
    ) -> Result<Delivery<'a>, Error> {
        let ca_key = VerifyingKey::from_bytes(&self.ca.ed25519).map_err(|_| Error::BadSignature)?;
        {
            let envelope = parse_envelope(frame)?;
            if envelope.recipient != self.id {
                return Err(Error::WrongRecipient);
            }
            if envelope.message_type != MessageType::PublicationResponse {
                return Err(Error::WrongMessageType);
            }
            if envelope.handler != expected_handler || expected_handler == HandlerId::NONE {
                return Err(Error::WrongHandler);
            }
            verify_envelope_signature(&envelope, &ca_key)?;
            replay.check_and_mark(envelope.sender, envelope.session_id, now_seconds)?;
        }
        let plaintext = open_in_place(
            frame,
            self.id,
            MessageType::PublicationResponse,
            &ca_key,
            &self.keys.x25519,
        )?;
        match parse_operation(plaintext)? {
            OperationRef::PublicationResponse {
                type_id,
                publisher,
                value,
            } => Ok(Delivery {
                type_id,
                publisher,
                handler: expected_handler,
                value,
            }),
            _ => Err(Error::WrongMessageType),
        }
    }

    fn request_into(
        &self,
        output: &mut [u8],
        message_type: MessageType,
        handler: HandlerId,
        rng: &mut impl CryptoRandom,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        if output.len() < MAX_FRAME_LEN {
            return Err(Error::Oversized);
        }
        let plaintext_len = encode(&mut output[HEADER_LEN..MAX_FRAME_LEN])?;
        let mut session = [0u8; 16];
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut session);
        rng.fill_bytes(&mut salt);
        seal_in_place(
            output,
            plaintext_len,
            message_type,
            self.id,
            AgentId::CA,
            handler,
            SessionId(session),
            salt,
            OneShotSecret::generate(rng),
            &self.ca.x25519,
            &self.keys.signing,
        )
    }

    #[cfg(feature = "alloc")]
    fn request_owned(
        &self,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<Vec<u8>, Error> {
        let mut frame = vec![0u8; MAX_FRAME_LEN];
        let length = encode(&mut frame)?;
        frame.truncate(length);
        Ok(frame)
    }
}

/// Authenticated publication delivered by the CA.
#[derive(Clone, Copy, Debug)]
pub struct Delivery<'a> {
    /// Publication type.
    pub type_id: TypeId,
    /// Original publisher.
    pub publisher: AgentId,
    /// Locally matched handler.
    pub handler: HandlerId,
    /// Decrypted value. The caller must avoid logging it.
    pub value: &'a [u8],
}

/// Copies a validated environment into bounded owned entries for desktop storage adapters.
#[cfg(feature = "alloc")]
pub fn copy_environment(environment: EnvironmentRef<'_>) -> Result<Vec<OwnedAttribute>, Error> {
    let mut result = Vec::with_capacity(environment.len());
    // The bounded ID space makes scanning deterministic and avoids exposing parser internals.
    for id in 0..=u16::MAX {
        if let Some(value) = environment.get(AttributeId(id)) {
            result.push(OwnedAttribute {
                id: AttributeId(id),
                value: OwnedValue::from(value),
            });
            if result.len() == environment.len() {
                return Ok(result);
            }
        }
    }
    if result.len() == environment.len() {
        Ok(result)
    } else {
        Err(Error::Malformed)
    }
}

/// Owned bounded environment entry used by desktop storage adapters.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedAttribute {
    /// Attribute ID.
    pub id: AttributeId,
    /// Typed value.
    pub value: OwnedValue,
}

/// Owned typed bounded value used by desktop storage adapters.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedValue {
    /// Boolean.
    Bool(bool),
    /// Signed integer.
    I64(i64),
    /// Bounded bytes.
    Bytes(Vec<u8>),
}

#[cfg(feature = "alloc")]
impl<'a> From<ValueRef<'a>> for OwnedValue {
    fn from(value: ValueRef<'a>) -> Self {
        match value {
            ValueRef::Bool(value) => Self::Bool(value),
            ValueRef::I64(value) => Self::I64(value),
            ValueRef::Bytes(value) => Self::Bytes(value.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_replay_cache_rejects_replay_and_reclaims_expired_entries() {
        let mut cache = FixedReplayCache::<1>::new(10);
        let sender = AgentId([1; 16]);
        let first = SessionId([2; 16]);
        let second = SessionId([3; 16]);

        assert_eq!(cache.check_and_mark(sender, first, 5), Ok(()));
        assert_eq!(cache.check_and_mark(sender, first, 6), Err(Error::Replay));
        assert_eq!(
            cache.check_and_mark(sender, second, 6),
            Err(Error::Capacity)
        );
        assert_eq!(cache.check_and_mark(sender, second, 15), Ok(()));
        assert_eq!(cache.len(), 1);
    }
}
