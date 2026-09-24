//! Platform adapter traits kept independent from `std`.

use core::future::Future;

use crate::{AgentId, Error, SessionId};

/// Infallible cryptographic byte source after platform-specific initialization.
///
/// Platform adapters seed such a generator fallibly from their operating system before invoking
/// protocol operations. This matches Dalek's consuming `EphemeralSecret` API.
pub trait CryptoRandom: rand_core::CryptoRng {}

impl<T: rand_core::CryptoRng + ?Sized> CryptoRandom for T {}

/// Monotonic or Unix clock supplied by the platform.
pub trait Clock {
    /// Returns monotonically non-decreasing seconds used only for expiry.
    fn now_seconds(&self) -> u64;
}

/// Atomic replay check and insertion.
pub trait ReplayProtector {
    /// Marks `(sender, session)` once or rejects it; implementations fail closed.
    fn check_and_mark(
        &mut self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error>;
}

/// Public-key directory abstraction.
pub trait KeyStore {
    /// Error type without secret material.
    type Error;
    /// Returns the Ed25519 and X25519 public keys for an identity.
    fn public_keys(&self, agent: AgentId) -> Result<([u8; 32], [u8; 32]), Self::Error>;
}

/// Bounded opaque storage abstraction for embedded adapters.
pub trait Storage {
    /// Error type.
    type Error;
    /// Fetches a value into caller-owned storage, returning bytes written.
    fn get(&self, namespace: u8, key: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
    /// Atomically replaces a bounded value.
    fn put(&mut self, namespace: u8, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
}

/// Framed transport abstraction.
pub trait Transport {
    /// Error type.
    type Error;
    /// Sends exactly one already-bounded envelope.
    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;
    /// Receives one envelope into caller storage.
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Allocation-free asynchronous framed transport.
///
/// This return-position-future interface is executor-neutral and can be implemented directly by
/// Embassy network/device adapters without `async-trait` boxing.
pub trait AsyncTransport {
    /// Error type.
    type Error;
    /// Sends exactly one already-bounded envelope.
    fn send(&mut self, frame: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
    /// Receives one envelope into caller-owned storage.
    fn receive(&mut self, output: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>>;
}
