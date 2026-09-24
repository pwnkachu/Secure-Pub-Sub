#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Allocation-free cryptographic and wire core for SecurePubSub/v1.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

mod codec;
mod crypto;
mod payload;
mod traits;
mod types;

pub use codec::{EnvelopeRef, encode_header, parse_envelope};
pub use crypto::{OneShotSecret, open_in_place, seal_in_place, verify_envelope_signature};
pub use payload::{
    AttributeRef, ClauseRef, EnvironmentIter, EnvironmentRef, OperationRef, PredicateRef, ValueRef,
    encode_environment, encode_publish, encode_response, encode_subscribe,
    encode_subscribe_permanent, parse_operation,
};
pub use traits::{
    AsyncTransport, Clock, CryptoRandom, KeyStore, ReplayProtector, Storage, Transport,
};
pub use types::*;
