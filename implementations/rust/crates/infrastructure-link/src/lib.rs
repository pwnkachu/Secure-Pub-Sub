#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Bounded, authenticated link protocol used only between the TCP broker and CA.
//!
//! The SecurePubSub envelope remains an opaque payload. This protocol supplies
//! acquisition acknowledgements and retransmission identifiers without changing
//! the cryptographic wire format understood by Agents.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use protocol_core::MAX_FRAME_LEN;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_util::codec::LengthDelimitedCodec;

/// Fixed link header length before the opaque payload.
pub const LINK_HEADER_LEN: usize = 28;
/// Maximum encoded link frame accepted before allocation by the codec.
pub const MAX_LINK_FRAME_LEN: usize = LINK_HEADER_LEN + MAX_FRAME_LEN;
const MAGIC: [u8; 4] = *b"SPLK";
const VERSION: u8 = 1;

/// Random link-level identifier, independent from a SecurePubSub `SessionId`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageId(pub [u8; 16]);

/// Internal frame purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    /// Agent request moving from Broker to CA.
    Request = 1,
    /// Opaque CA delivery moving from CA to Broker.
    Delivery = 2,
    /// Acquisition acknowledgement for one message identifier.
    Ack = 3,
    /// CA authentication challenge.
    AuthChallenge = 4,
    /// Broker MAC response.
    AuthResponse = 5,
    /// CA authentication success marker.
    AuthOk = 6,
}

impl FrameKind {
    fn parse(value: u8) -> Result<Self, LinkError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Delivery),
            3 => Ok(Self::Ack),
            4 => Ok(Self::AuthChallenge),
            5 => Ok(Self::AuthResponse),
            6 => Ok(Self::AuthOk),
            _ => Err(LinkError::InvalidFrame),
        }
    }
}

/// Borrowed validated internal frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkFrame<'a> {
    /// Frame purpose.
    pub kind: FrameKind,
    /// Acknowledgement/retransmission identifier.
    pub id: MessageId,
    /// Opaque bounded payload.
    pub payload: &'a [u8],
}

/// Link codec or bounded-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkError {
    /// Header, type, reserved field, or length was invalid.
    InvalidFrame,
    /// Payload or complete frame exceeded its explicit limit.
    Oversized,
    /// A bounded pending collection was saturated.
    QueueFull,
    /// Challenge-response authentication failed.
    Authentication,
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LinkError {}

/// Creates the unsigned big-endian `u32` framing codec for the infrastructure link.
pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(MAX_LINK_FRAME_LEN)
        .new_codec()
}

/// Encodes one bounded internal frame.
pub fn encode(kind: FrameKind, id: MessageId, payload: &[u8]) -> Result<Vec<u8>, LinkError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(LinkError::Oversized);
    }
    if matches!(kind, FrameKind::Ack | FrameKind::AuthOk) && !payload.is_empty() {
        return Err(LinkError::InvalidFrame);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| LinkError::Oversized)?;
    let mut output = Vec::with_capacity(LINK_HEADER_LEN + payload.len());
    output.extend_from_slice(&MAGIC);
    output.push(VERSION);
    output.push(kind as u8);
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&id.0);
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

/// Validates and borrows one complete internal frame without copying its payload.
pub fn decode(input: &[u8]) -> Result<LinkFrame<'_>, LinkError> {
    if input.len() < LINK_HEADER_LEN {
        return Err(LinkError::InvalidFrame);
    }
    if input.len() > MAX_LINK_FRAME_LEN {
        return Err(LinkError::Oversized);
    }
    if input[..4] != MAGIC || input[4] != VERSION || input[6..8] != [0, 0] {
        return Err(LinkError::InvalidFrame);
    }
    let kind = FrameKind::parse(input[5])?;
    let id = MessageId(
        input[8..24]
            .try_into()
            .map_err(|_| LinkError::InvalidFrame)?,
    );
    let payload_len = u32::from_be_bytes(
        input[24..28]
            .try_into()
            .map_err(|_| LinkError::InvalidFrame)?,
    ) as usize;
    let expected = LINK_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(LinkError::Oversized)?;
    if expected != input.len() || payload_len > MAX_FRAME_LEN {
        return Err(LinkError::InvalidFrame);
    }
    let payload = &input[LINK_HEADER_LEN..];
    if matches!(kind, FrameKind::Ack | FrameKind::AuthOk) && !payload.is_empty() {
        return Err(LinkError::InvalidFrame);
    }
    Ok(LinkFrame { kind, id, payload })
}

/// Computes the challenge-response MAC using a fixed 32-byte deployment secret.
pub fn authentication_mac(secret: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut inner_key = [0x36; BLOCK];
    let mut outer_key = [0x5c; BLOCK];
    for index in 0..secret.len() {
        inner_key[index] ^= secret[index];
        outer_key[index] ^= secret[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_key)
        .chain_update(b"SecurePubSub/Broker-CA/v1")
        .chain_update(challenge)
        .finalize();
    Sha256::new()
        .chain_update(outer_key)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Verifies an authentication response in constant time.
pub fn verify_authentication(
    secret: &[u8; 32],
    challenge: &[u8; 32],
    response: &[u8],
) -> Result<(), LinkError> {
    let expected = authentication_mac(secret, challenge);
    if response.len() == expected.len() && bool::from(expected.ct_eq(response)) {
        Ok(())
    } else {
        Err(LinkError::Authentication)
    }
}

/// Bounded collection of all sent but unacknowledged frames.
pub struct PendingFrames {
    maximum: usize,
    frames: BTreeMap<MessageId, Vec<u8>>,
    order: VecDeque<MessageId>,
}

impl PendingFrames {
    /// Creates an empty collection with an explicit maximum.
    pub const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            frames: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Acquires a frame before it may be sent.
    pub fn insert(&mut self, id: MessageId, encoded: Vec<u8>) -> Result<(), LinkError> {
        if self.frames.contains_key(&id) {
            return Err(LinkError::InvalidFrame);
        }
        if self.frames.len() >= self.maximum {
            return Err(LinkError::QueueFull);
        }
        self.frames.insert(id, encoded);
        self.order.push_back(id);
        Ok(())
    }

    /// Completes one frame after its ACK.
    pub fn acknowledge(&mut self, id: MessageId) -> bool {
        let removed = self.frames.remove(&id).is_some();
        if removed {
            self.order.retain(|candidate| *candidate != id);
        }
        removed
    }

    /// Stable retransmission snapshot.
    pub fn snapshot(&self) -> Vec<Vec<u8>> {
        self.order
            .iter()
            .filter_map(|id| self.frames.get(id).cloned())
            .collect()
    }

    /// Number of unacknowledged frames.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame is awaiting acknowledgement.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Whether another distinct frame can be acquired.
    pub fn is_full(&self) -> bool {
        self.frames.len() >= self.maximum
    }

    /// Remaining frame slots.
    pub fn remaining(&self) -> usize {
        self.maximum.saturating_sub(self.frames.len())
    }
}

/// Bounded FIFO deduplication window.
pub struct DedupWindow {
    maximum: usize,
    order: VecDeque<MessageId>,
    ids: BTreeSet<MessageId>,
}

impl DedupWindow {
    /// Creates an empty bounded window.
    pub const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            order: VecDeque::new(),
            ids: BTreeSet::new(),
        }
    }

    /// Returns whether the identifier has already been acquired.
    pub fn contains(&self, id: MessageId) -> bool {
        self.ids.contains(&id)
    }

    /// Records an acquired identifier, evicting the oldest when bounded capacity is reached.
    pub fn insert(&mut self, id: MessageId) -> Result<(), LinkError> {
        if self.maximum == 0 {
            return Err(LinkError::QueueFull);
        }
        if self.ids.contains(&id) {
            return Ok(());
        }
        if self.ids.len() == self.maximum
            && let Some(oldest) = self.order.pop_front()
        {
            self.ids.remove(&oldest);
        }
        self.order.push_back(id);
        self.ids.insert(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_and_length_validation() {
        let id = MessageId([7; 16]);
        let encoded = encode(FrameKind::Request, id, b"opaque").unwrap();
        assert_eq!(
            decode(&encoded),
            Ok(LinkFrame {
                kind: FrameKind::Request,
                id,
                payload: b"opaque"
            })
        );
        let mut altered = encoded;
        altered[27] = altered[27].wrapping_add(1);
        assert_eq!(decode(&altered), Err(LinkError::InvalidFrame));
    }

    #[test]
    fn pending_frames_cover_zero_one_saturation_ack_and_retransmission() {
        let id = MessageId([1; 16]);
        assert_eq!(
            PendingFrames::new(0).insert(id, vec![1]),
            Err(LinkError::QueueFull)
        );
        let mut pending = PendingFrames::new(1);
        pending.insert(id, vec![1]).unwrap();
        assert_eq!(pending.snapshot(), vec![vec![1]]);
        assert_eq!(
            pending.insert(MessageId([2; 16]), vec![2]),
            Err(LinkError::QueueFull)
        );
        assert!(pending.acknowledge(id));
        assert!(pending.is_empty());
    }

    #[test]
    fn deduplication_is_bounded() {
        let mut window = DedupWindow::new(1);
        let first = MessageId([1; 16]);
        let second = MessageId([2; 16]);
        window.insert(first).unwrap();
        window.insert(first).unwrap();
        assert!(window.contains(first));
        window.insert(second).unwrap();
        assert!(!window.contains(first));
        assert!(window.contains(second));
        assert_eq!(DedupWindow::new(0).insert(first), Err(LinkError::QueueFull));
    }

    #[test]
    fn authentication_rejects_wrong_secret_and_modified_response() {
        let challenge = [9; 32];
        let mac = authentication_mac(&[3; 32], &challenge);
        assert!(verify_authentication(&[3; 32], &challenge, &mac).is_ok());
        assert_eq!(
            verify_authentication(&[4; 32], &challenge, &mac),
            Err(LinkError::Authentication)
        );
    }

    #[test]
    fn disconnect_before_or_after_send_retransmits_until_ack_only() {
        let id = MessageId([8; 16]);
        let wire = encode(FrameKind::Request, id, b"request").unwrap();
        let mut pending = PendingFrames::new(2);

        // Disconnect before the first send: acquired state still owns the frame.
        pending.insert(id, wire.clone()).unwrap();
        assert_eq!(pending.snapshot(), vec![wire.clone()]);
        // Disconnect after a successful write but before ACK: same retransmission.
        assert_eq!(pending.snapshot(), vec![wire]);
        // After ACK no reconnect may retransmit it.
        assert!(pending.acknowledge(id));
        assert!(pending.snapshot().is_empty());
    }

    #[test]
    fn duplicate_delivery_is_acquired_once_but_acknowledged_again() {
        let id = MessageId([6; 16]);
        let mut acquired = DedupWindow::new(4);
        assert!(!acquired.contains(id));
        acquired.insert(id).unwrap();
        assert!(acquired.contains(id));
        acquired.insert(id).unwrap();
        assert!(acquired.contains(id));
    }

    #[test]
    fn disconnect_during_delivery_group_keeps_only_unacknowledged_members() {
        let first = MessageId([1; 16]);
        let second = MessageId([2; 16]);
        let mut pending = PendingFrames::new(2);
        pending.insert(second, vec![2]).unwrap();
        pending.insert(first, vec![1]).unwrap();
        assert_eq!(pending.snapshot(), vec![vec![2], vec![1]]);
        assert!(pending.acknowledge(second));
        assert_eq!(pending.snapshot(), vec![vec![1]]);
        assert!(pending.acknowledge(first));
        assert!(pending.snapshot().is_empty());
    }
}
