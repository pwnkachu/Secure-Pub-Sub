//! Protocol constants and small wire-safe identifiers.

use core::fmt;

/// ASCII wire magic including its NUL terminator.
pub const MAGIC: [u8; 8] = *b"SPUBSUB\0";
/// Human-readable protocol identifier used by the KDF.
pub const PROTOCOL_ID: &[u8] = b"SecurePubSub/v1";
/// Current wire version.
pub const VERSION: u8 = 1;
/// Bytes before ciphertext in an envelope.
pub const HEADER_LEN: usize = 148;
/// Detached Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Maximum encrypted application payload.
pub const MAX_PLAINTEXT_LEN: usize = 4096;
/// Maximum complete envelope length.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PLAINTEXT_LEN + TAG_LEN + SIGNATURE_LEN;
/// Maximum attributes in an environment.
pub const MAX_ATTRIBUTES: usize = 16;
/// Maximum conjunction clauses.
pub const MAX_CLAUSES: usize = 8;
/// Maximum byte-string attribute value.
pub const MAX_ATTRIBUTE_BYTES: usize = 64;
/// Maximum publication value.
pub const MAX_VALUE_BYTES: usize = 3072;

/// Stable 128-bit agent identity provisioned by the CA.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentId(pub [u8; 16]);

impl AgentId {
    /// Reserved recipient/sender identity for the CA.
    pub const CA: Self = Self([0; 16]);
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Random 128-bit identifier, unique for a one-message session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(pub [u8; 16]);

/// Application handler identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandlerId(pub [u8; 16]);

impl HandlerId {
    /// Empty handler used only by operations that do not carry a handler.
    pub const NONE: Self = Self([0; 16]);
}

/// Bounded application type identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypeId(pub u32);

/// Environment attribute identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttributeId(pub u16);

/// Signed and KDF-bound envelope purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    /// Agent sets its typed environment at the CA.
    SetEnvironment = 1,
    /// Agent registers a permanent subscription.
    SubscribePermanent = 2,
    /// Agent submits a publication.
    Publish = 3,
    /// CA delivers a publication to one subscriber.
    PublicationResponse = 4,
    /// Agent registers a one-shot subscription.
    Subscribe = 5,
}

impl MessageType {
    /// Parses the canonical wire discriminant.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SetEnvironment),
            2 => Some(Self::SubscribePermanent),
            3 => Some(Self::Publish),
            4 => Some(Self::PublicationResponse),
            5 => Some(Self::Subscribe),
            _ => None,
        }
    }

    /// Direction encoded into KDF context.
    pub const fn direction(self) -> u8 {
        match self {
            Self::PublicationResponse => 2,
            _ => 1,
        }
    }

    /// Domain string encoded into KDF context.
    pub const fn domain(self) -> &'static [u8] {
        match self {
            Self::SetEnvironment => b"env",
            Self::SubscribePermanent => b"subscription",
            Self::Subscribe => b"subscription-one-shot",
            Self::Publish => b"publication-request",
            Self::PublicationResponse => b"publication-response",
        }
    }
}

/// Comparison operator in a bounded conjunction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operator {
    /// Equal.
    Eq = 1,
    /// Not equal.
    Ne = 2,
    /// Less than.
    Lt = 3,
    /// Less or equal.
    Le = 4,
    /// Greater than.
    Gt = 5,
    /// Greater or equal.
    Ge = 6,
}

impl Operator {
    /// Parses the canonical wire discriminant.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Eq),
            2 => Some(Self::Ne),
            3 => Some(Self::Lt),
            4 => Some(Self::Le),
            5 => Some(Self::Gt),
            6 => Some(Self::Ge),
            _ => None,
        }
    }
}

/// Public protocol errors; cryptographic failures deliberately share one variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Structurally invalid or non-canonical input.
    Malformed,
    /// Unsupported protocol version.
    UnsupportedVersion,
    /// Input or output exceeds an explicit bound.
    Oversized,
    /// Ed25519 verification failed.
    BadSignature,
    /// Replay protector rejected a session.
    Replay,
    /// Key agreement, KDF, or AEAD operation failed.
    CryptoFailure,
    /// The envelope is addressed to a different principal.
    WrongRecipient,
    /// Message kind is not valid for this state/role.
    WrongMessageType,
    /// Handler does not match a locally registered handler.
    WrongHandler,
    /// RNG failed.
    RandomFailure,
    /// Storage reached capacity or failed closed.
    Capacity,
    /// The CA rejected an environment without disclosing policy details.
    UnauthorizedEnvironment,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
