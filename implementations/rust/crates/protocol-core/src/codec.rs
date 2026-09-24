//! Canonical, zero-copy envelope codec.

use crate::{
    AgentId, Error, HEADER_LEN, HandlerId, MAGIC, MAX_FRAME_LEN, MAX_PLAINTEXT_LEN, MessageType,
    SIGNATURE_LEN, SessionId, TAG_LEN, VERSION,
};

/// Borrowed view of a validated complete envelope.
#[derive(Clone, Copy, Debug)]
pub struct EnvelopeRef<'a> {
    /// Purpose and direction.
    pub message_type: MessageType,
    /// Authenticated sender.
    pub sender: AgentId,
    /// Intended recipient.
    pub recipient: AgentId,
    /// Optional operation handler.
    pub handler: HandlerId,
    /// Random session identifier.
    pub session_id: SessionId,
    /// Sender's per-message X25519 public key.
    pub ephemeral_public: &'a [u8; 32],
    /// Public HKDF salt.
    pub salt: &'a [u8; 32],
    /// Ciphertext without detached AEAD tag.
    pub ciphertext: &'a [u8],
    /// Detached Poly1305 tag.
    pub tag: &'a [u8; TAG_LEN],
    /// Ed25519 signature over all prior bytes.
    pub signature: &'a [u8; SIGNATURE_LEN],
    /// Canonical header used as AEAD associated data.
    pub header: &'a [u8],
    /// Canonical signed transcript (header, ciphertext, and tag).
    pub signed_bytes: &'a [u8],
}

/// Writes the canonical fixed header and returns the complete envelope length.
#[allow(clippy::too_many_arguments)]
pub fn encode_header(
    output: &mut [u8],
    message_type: MessageType,
    sender: AgentId,
    recipient: AgentId,
    handler: HandlerId,
    session_id: SessionId,
    ephemeral_public: &[u8; 32],
    salt: &[u8; 32],
    ciphertext_len: usize,
) -> Result<usize, Error> {
    if ciphertext_len > MAX_PLAINTEXT_LEN {
        return Err(Error::Oversized);
    }
    let total_len = HEADER_LEN
        .checked_add(ciphertext_len)
        .and_then(|v| v.checked_add(TAG_LEN + SIGNATURE_LEN))
        .ok_or(Error::Oversized)?;
    if output.len() < HEADER_LEN || total_len > MAX_FRAME_LEN {
        return Err(Error::Oversized);
    }
    let total_u32 = u32::try_from(total_len).map_err(|_| Error::Oversized)?;
    let cipher_u32 = u32::try_from(ciphertext_len).map_err(|_| Error::Oversized)?;
    output[0..8].copy_from_slice(&MAGIC);
    output[8] = VERSION;
    output[9] = message_type as u8;
    output[10..12].copy_from_slice(&0u16.to_be_bytes());
    output[12..16].copy_from_slice(&total_u32.to_be_bytes());
    output[16..32].copy_from_slice(&sender.0);
    output[32..48].copy_from_slice(&recipient.0);
    output[48..64].copy_from_slice(&handler.0);
    output[64..80].copy_from_slice(&session_id.0);
    output[80..112].copy_from_slice(ephemeral_public);
    output[112..144].copy_from_slice(salt);
    output[144..148].copy_from_slice(&cipher_u32.to_be_bytes());
    Ok(total_len)
}

/// Parses exactly one canonical envelope without allocation.
pub fn parse_envelope(input: &[u8]) -> Result<EnvelopeRef<'_>, Error> {
    if input.len() < HEADER_LEN + TAG_LEN + SIGNATURE_LEN {
        return Err(Error::Malformed);
    }
    if input.len() > MAX_FRAME_LEN {
        return Err(Error::Oversized);
    }
    if input.get(0..8) != Some(MAGIC.as_slice()) {
        return Err(Error::Malformed);
    }
    if input[8] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let message_type = MessageType::from_u8(input[9]).ok_or(Error::Malformed)?;
    if input[10..12] != [0, 0] {
        return Err(Error::Malformed);
    }
    let total_len = read_u32(&input[12..16])? as usize;
    if total_len != input.len() {
        return Err(Error::Malformed);
    }
    let ciphertext_len = read_u32(&input[144..148])? as usize;
    if ciphertext_len > MAX_PLAINTEXT_LEN {
        return Err(Error::Oversized);
    }
    let expected = HEADER_LEN
        .checked_add(ciphertext_len)
        .and_then(|v| v.checked_add(TAG_LEN + SIGNATURE_LEN))
        .ok_or(Error::Oversized)?;
    if expected != total_len {
        return Err(Error::Malformed);
    }
    let ciphertext_end = HEADER_LEN + ciphertext_len;
    let tag_end = ciphertext_end + TAG_LEN;
    let ephemeral_public = array_ref(&input[80..112])?;
    let salt = array_ref(&input[112..144])?;
    let tag = array_ref(&input[ciphertext_end..tag_end])?;
    let signature = array_ref(&input[tag_end..total_len])?;
    Ok(EnvelopeRef {
        message_type,
        sender: AgentId(array_copy(&input[16..32])?),
        recipient: AgentId(array_copy(&input[32..48])?),
        handler: HandlerId(array_copy(&input[48..64])?),
        session_id: SessionId(array_copy(&input[64..80])?),
        ephemeral_public,
        salt,
        ciphertext: &input[HEADER_LEN..ciphertext_end],
        tag,
        signature,
        header: &input[..HEADER_LEN],
        signed_bytes: &input[..tag_end],
    })
}

fn read_u32(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array_copy(bytes)?))
}

fn array_copy<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Malformed)
}

fn array_ref<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn decoder_never_panics_and_only_accepts_exact_lengths(data in proptest::collection::vec(any::<u8>(), 0..5000)) {
            if let Ok(envelope) = parse_envelope(&data) {
                prop_assert_eq!(envelope.signed_bytes.len() + SIGNATURE_LEN, data.len());
                prop_assert!(envelope.ciphertext.len() <= MAX_PLAINTEXT_LEN);
            }
        }
    }

    #[test]
    fn rejects_trailing_truncated_and_oversized() {
        let mut frame = [0u8; HEADER_LEN + TAG_LEN + SIGNATURE_LEN];
        let length = encode_header(
            &mut frame,
            MessageType::SetEnvironment,
            AgentId([1; 16]),
            AgentId::CA,
            HandlerId::NONE,
            SessionId([2; 16]),
            &[3; 32],
            &[4; 32],
            0,
        )
        .unwrap_or(0);
        assert!(parse_envelope(&frame[..length]).is_ok());
        assert!(matches!(
            parse_envelope(&frame[..length - 1]),
            Err(Error::Malformed)
        ));
        let mut trailing = frame.to_vec();
        trailing.push(0);
        assert!(matches!(parse_envelope(&trailing), Err(Error::Malformed)));
        assert!(matches!(
            parse_envelope(&std::vec![0; MAX_FRAME_LEN + 1]),
            Err(Error::Oversized)
        ));
    }
}
