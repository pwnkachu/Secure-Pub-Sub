//! Authenticated ECIES-like hybrid encryption construction based on ephemeral-static X25519,
//! HKDF-SHA256, ChaCha20-Poly1305, and Ed25519 signatures.
//!
//! This construction is neither standard ECIES nor HPKE.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, Tag,
    aead::{AeadInOut, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    AgentId, CryptoRandom, EnvelopeRef, Error, HEADER_LEN, HandlerId, MessageType, PROTOCOL_ID,
    SIGNATURE_LEN, SessionId, TAG_LEN, VERSION, encode_header, parse_envelope,
};

type DerivedKeyNonce = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>);

/// Compile-time one-use X25519 secret; key agreement consumes it.
pub struct OneShotSecret(EphemeralSecret);

impl OneShotSecret {
    /// Generates a fresh Dalek ephemeral secret from an initialized CSPRNG.
    pub fn generate(rng: &mut impl CryptoRandom) -> Self {
        Self(EphemeralSecret::random_from_rng(rng))
    }

    /// Returns the public key without exposing secret material.
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    fn agree(self, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let shared = self.0.diffie_hellman(&PublicKey::from(*peer));
        let bytes = shared.to_bytes();
        if bool::from(bytes.ct_eq(&[0u8; 32])) {
            return Err(Error::CryptoFailure);
        }
        Ok(Zeroizing::new(bytes))
    }
}

/// Seals plaintext already located at `HEADER_LEN..HEADER_LEN + plaintext_len`.
///
/// The output buffer must have room for the fixed header, plaintext, tag and signature.
#[allow(clippy::too_many_arguments)]
pub fn seal_in_place(
    output: &mut [u8],
    plaintext_len: usize,
    message_type: MessageType,
    sender: AgentId,
    recipient: AgentId,
    handler: HandlerId,
    session_id: SessionId,
    salt: [u8; 32],
    ephemeral_secret: OneShotSecret,
    recipient_x25519: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<usize, Error> {
    let ephemeral_public = ephemeral_secret.public_key();
    let total_len = encode_header(
        output,
        message_type,
        sender,
        recipient,
        handler,
        session_id,
        &ephemeral_public,
        &salt,
        plaintext_len,
    )?;
    if output.len() < total_len {
        return Err(Error::Oversized);
    }
    let shared = ephemeral_secret.agree(recipient_x25519)?;
    let (key, nonce) = derive_key_nonce(
        &shared,
        &salt,
        message_type,
        sender,
        recipient,
        session_id,
        &ephemeral_public,
    )?;
    let key_ref: &Key = (&key[..]).try_into().map_err(|_| Error::CryptoFailure)?;
    let nonce_ref: &Nonce = (&nonce[..]).try_into().map_err(|_| Error::CryptoFailure)?;
    let cipher = ChaCha20Poly1305::new(key_ref);
    let ciphertext_end = HEADER_LEN + plaintext_len;
    let (prefix_and_ciphertext, tail) = output.split_at_mut(ciphertext_end);
    let (header, ciphertext) = prefix_and_ciphertext.split_at_mut(HEADER_LEN);
    let tag = cipher
        .encrypt_inout_detached(nonce_ref, header, ciphertext.into())
        .map_err(|_| Error::CryptoFailure)?;
    tail[..TAG_LEN].copy_from_slice(&tag);
    let signed_end = ciphertext_end + TAG_LEN;
    let signature = signing_key.sign(&output[..signed_end]);
    output[signed_end..signed_end + SIGNATURE_LEN].copy_from_slice(&signature.to_bytes());
    Ok(total_len)
}

/// Verifies the signature over a canonical envelope before key agreement/decryption.
pub fn verify_envelope_signature(
    envelope: &EnvelopeRef<'_>,
    verifying_key: &VerifyingKey,
) -> Result<(), Error> {
    let signature = Signature::from_bytes(envelope.signature);
    verifying_key
        .verify_strict(envelope.signed_bytes, &signature)
        .map_err(|_| Error::BadSignature)
}

/// Verifies, checks role fields, then decrypts ciphertext in the supplied frame.
///
/// Replay checks intentionally remain at the caller so they can occur after signature
/// verification and before this comparatively expensive key agreement.
pub fn open_in_place<'a>(
    frame: &'a mut [u8],
    expected_recipient: AgentId,
    expected_type: MessageType,
    sender_verifying_key: &VerifyingKey,
    recipient_x25519_secret: &StaticSecret,
) -> Result<&'a mut [u8], Error> {
    {
        let envelope = parse_envelope(frame)?;
        if envelope.recipient != expected_recipient {
            return Err(Error::WrongRecipient);
        }
        if envelope.message_type != expected_type {
            return Err(Error::WrongMessageType);
        }
        verify_envelope_signature(&envelope, sender_verifying_key)?;
    }
    let envelope = parse_envelope(frame)?;
    let shared_secret =
        recipient_x25519_secret.diffie_hellman(&PublicKey::from(*envelope.ephemeral_public));
    let shared = Zeroizing::new(shared_secret.to_bytes());
    if bool::from(shared.as_ref().ct_eq(&[0u8; 32])) {
        return Err(Error::CryptoFailure);
    }
    let (key, nonce) = derive_key_nonce(
        &shared,
        envelope.salt,
        envelope.message_type,
        envelope.sender,
        envelope.recipient,
        envelope.session_id,
        envelope.ephemeral_public,
    )?;
    let ciphertext_len = envelope.ciphertext.len();
    let tag_bytes = *envelope.tag;
    let key_ref: &Key = (&key[..]).try_into().map_err(|_| Error::CryptoFailure)?;
    let nonce_ref: &Nonce = (&nonce[..]).try_into().map_err(|_| Error::CryptoFailure)?;
    let tag_ref: &Tag = tag_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;
    let cipher = ChaCha20Poly1305::new(key_ref);
    let (prefix_and_ciphertext, _) = frame.split_at_mut(HEADER_LEN + ciphertext_len);
    let (header, ciphertext) = prefix_and_ciphertext.split_at_mut(HEADER_LEN);
    cipher
        .decrypt_inout_detached(nonce_ref, header, ciphertext.into(), tag_ref)
        .map_err(|_| Error::CryptoFailure)?;
    Ok(ciphertext)
}

fn derive_key_nonce(
    shared: &[u8; 32],
    salt: &[u8; 32],
    message_type: MessageType,
    sender: AgentId,
    recipient: AgentId,
    session_id: SessionId,
    ephemeral_public: &[u8; 32],
) -> Result<DerivedKeyNonce, Error> {
    let mut context = [0u8; 128];
    let mut cursor = 0usize;
    append(&mut context, &mut cursor, PROTOCOL_ID)?;
    append(&mut context, &mut cursor, &[VERSION])?;
    append(
        &mut context,
        &mut cursor,
        &[message_type.direction(), message_type as u8],
    )?;
    append(&mut context, &mut cursor, message_type.domain())?;
    append(&mut context, &mut cursor, &sender.0)?;
    append(&mut context, &mut cursor, &recipient.0)?;
    append(&mut context, &mut cursor, ephemeral_public)?;
    append(&mut context, &mut cursor, &session_id.0)?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = Zeroizing::new([0u8; 12]);
    expand_label(
        &hkdf,
        &context[..cursor],
        b"aead-key/chacha20poly1305",
        &mut *key,
    )?;
    expand_label(
        &hkdf,
        &context[..cursor],
        b"aead-nonce/one-message",
        &mut *nonce,
    )?;
    Ok((key, nonce))
}

fn expand_label(
    hkdf: &Hkdf<Sha256>,
    context: &[u8],
    label: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    let mut info = [0u8; 160];
    let mut cursor = 0usize;
    append(&mut info, &mut cursor, context)?;
    append(&mut info, &mut cursor, label)?;
    hkdf.expand(&info[..cursor], output)
        .map_err(|_| Error::CryptoFailure)
}

fn append(output: &mut [u8], cursor: &mut usize, input: &[u8]) -> Result<(), Error> {
    let end = cursor
        .checked_add(input.len())
        .ok_or(Error::CryptoFailure)?;
    let destination = output.get_mut(*cursor..end).ok_or(Error::CryptoFailure)?;
    destination.copy_from_slice(input);
    *cursor = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand_core::SeedableRng;
    use x25519_dalek::x25519;

    fn sealed_frame() -> (std::vec::Vec<u8>, StaticSecret, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let verifying = signing.verifying_key();
        let recipient = StaticSecret::from([9; 32]);
        let recipient_public = PublicKey::from(&recipient).to_bytes();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let mut frame = std::vec![0u8; crate::MAX_FRAME_LEN];
        frame[HEADER_LEN..HEADER_LEN + 5].copy_from_slice(b"hello");
        let length = seal_in_place(
            &mut frame,
            5,
            MessageType::Publish,
            AgentId([1; 16]),
            AgentId::CA,
            HandlerId::NONE,
            SessionId([2; 16]),
            [3; 32],
            OneShotSecret::generate(&mut rng),
            &recipient_public,
            &signing,
        )
        .unwrap_or(0);
        frame.truncate(length);
        (frame, recipient, verifying)
    }

    #[test]
    fn rfc7748_x25519_known_answer() {
        let alice_private =
            hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_public = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(alice_private, bob_public), expected);
    }

    #[test]
    fn rfc8032_ed25519_known_answer() {
        let secret = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                             "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let signing = SigningKey::from_bytes(&secret);
        assert_eq!(signing.verifying_key().to_bytes(), public);
        assert_eq!(signing.sign(b"").to_bytes(), signature);
    }

    #[test]
    fn rfc5869_hkdf_sha256_known_answer() {
        let ikm = hex!(
            "0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b
                        0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b"
        );
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex!("3cb25f25faacd57a90434f64d0362f2a"
                            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            "34007208d5b887185865");
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut output = [0u8; 42];
        assert!(hkdf.expand(&info, &mut output).is_ok());
        assert_eq!(output, expected);
    }

    #[test]
    fn seal_open_round_trip() {
        let (mut frame, recipient, verifying) = sealed_frame();
        let plaintext = open_in_place(
            &mut frame,
            AgentId::CA,
            MessageType::Publish,
            &verifying,
            &recipient,
        );
        assert_eq!(plaintext.map(|value| &*value), Ok(b"hello".as_slice()));
    }

    #[test]
    fn every_signed_field_rejects_single_byte_tampering() {
        let (frame, recipient, verifying) = sealed_frame();
        let offsets = [
            0usize, 8, 9, 10, 12, 16, 32, 48, 64, 80, 112, 144, 148, 153, 164, 169,
        ];
        for offset in offsets {
            let mut altered = frame.clone();
            if let Some(byte) = altered.get_mut(offset) {
                *byte ^= 1;
            }
            assert!(
                open_in_place(
                    &mut altered,
                    AgentId::CA,
                    MessageType::Publish,
                    &verifying,
                    &recipient,
                )
                .is_err(),
                "offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn wrong_recipient_and_message_role_fail_before_decryption() {
        let (frame, recipient, verifying) = sealed_frame();
        let mut wrong_recipient = frame.clone();
        assert_eq!(
            open_in_place(
                &mut wrong_recipient,
                AgentId([99; 16]),
                MessageType::Publish,
                &verifying,
                &recipient,
            )
            .map(|_| ()),
            Err(Error::WrongRecipient)
        );
        let mut wrong_type = frame;
        assert_eq!(
            open_in_place(
                &mut wrong_type,
                AgentId::CA,
                MessageType::Subscribe,
                &verifying,
                &recipient,
            )
            .map(|_| ()),
            Err(Error::WrongMessageType)
        );
    }

    #[test]
    fn all_zero_x25519_peer_is_rejected() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let mut frame = std::vec![0u8; crate::MAX_FRAME_LEN];
        frame[HEADER_LEN] = 1;
        let result = seal_in_place(
            &mut frame,
            1,
            MessageType::Publish,
            AgentId([1; 16]),
            AgentId::CA,
            HandlerId::NONE,
            SessionId([2; 16]),
            [3; 32],
            OneShotSecret::generate(&mut rng),
            &[0; 32],
            &signing,
        );
        assert_eq!(result, Err(Error::CryptoFailure));
    }

    #[test]
    fn kdf_domains_and_message_types_do_not_collide() {
        let shared = [1; 32];
        let salt = [2; 32];
        let common = (AgentId([3; 16]), AgentId::CA, SessionId([4; 16]), [5; 32]);
        let publish = derive_key_nonce(
            &shared,
            &salt,
            MessageType::Publish,
            common.0,
            common.1,
            common.2,
            &common.3,
        );
        let subscribe = derive_key_nonce(
            &shared,
            &salt,
            MessageType::Subscribe,
            common.0,
            common.1,
            common.2,
            &common.3,
        );
        let permanent = derive_key_nonce(
            &shared,
            &salt,
            MessageType::SubscribePermanent,
            common.0,
            common.1,
            common.2,
            &common.3,
        );
        assert!(matches!(
            (publish, subscribe, permanent),
            (Ok((a, _)), Ok((b, _)), Ok((c, _))) if *a != *b && *a != *c && *b != *c
        ));
    }
}
