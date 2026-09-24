#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Configuration and key-loading helpers shared by deployable Agent applications.

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use agent_core::{Agent, AgentKeys, CaPublicKeys};
use protocol_core::AgentId;
use serde::Deserialize;

/// Common, domain-independent Agent configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Stable 16-byte identity encoded as 32 hexadecimal digits.
    pub agent_id: String,
    /// Broker TCP address.
    pub broker_address: String,
    /// Timeout for one TCP connection attempt.
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    /// Initial delay before retrying a lost Broker connection.
    #[serde(default = "default_reconnect_min_seconds")]
    pub reconnect_min_seconds: u64,
    /// Maximum bounded reconnect delay.
    #[serde(default = "default_reconnect_max_seconds")]
    pub reconnect_max_seconds: u64,
    /// File containing the Agent Ed25519 secret as 64 hexadecimal digits.
    pub ed25519_secret_file: String,
    /// File containing the Agent X25519 secret as 64 hexadecimal digits.
    pub x25519_secret_file: String,
    /// File containing the CA Ed25519 public key as 64 hexadecimal digits.
    pub ca_ed25519_public_file: String,
    /// File containing the CA X25519 public key as 64 hexadecimal digits.
    pub ca_x25519_public_file: String,
}

const fn default_connect_timeout_seconds() -> u64 {
    10
}

const fn default_reconnect_min_seconds() -> u64 {
    1
}

const fn default_reconnect_max_seconds() -> u64 {
    30
}

/// Connects an Agent to the public Broker listener and sends its routing hello.
///
/// Failures are retried forever with bounded exponential backoff. The hello is
/// routing metadata only; signed envelopes remain the authentication mechanism.
pub async fn connect_agent(config: &AgentConfig, identity: AgentId) -> transport::FramedTransport {
    let deadline = std::time::Duration::from_secs(config.connect_timeout_seconds.max(1));
    let minimum = std::time::Duration::from_secs(config.reconnect_min_seconds.max(1));
    let maximum = std::time::Duration::from_secs(
        config
            .reconnect_max_seconds
            .max(config.reconnect_min_seconds)
            .max(1),
    );
    let mut backoff = minimum;
    loop {
        if let Ok(mut transport) =
            transport::FramedTransport::connect(&config.broker_address, deadline).await
            && transport.send_hello(identity).await.is_ok()
        {
            return transport;
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(maximum);
    }
}

/// Sends one already-built envelope, reconnecting and resending after a socket failure.
///
/// A resend can reach the CA after the first write actually succeeded; protocol replay
/// protection makes that retry fail closed instead of applying an operation twice.
pub async fn send_agent_frame(
    config: &AgentConfig,
    identity: AgentId,
    transport: &mut transport::FramedTransport,
    frame: &[u8],
) {
    loop {
        if transport.send(frame).await.is_ok() {
            return;
        }
        *transport = connect_agent(config, identity).await;
    }
}

/// Performs one on-demand `connect -> hello -> send -> close` operation.
///
/// This is intended for publishers that do not immediately need a response.
/// The returned success means the Broker TCP stack accepted the frame; it is
/// not a CA application acknowledgement.
pub async fn send_on_demand(config: &AgentConfig, identity: AgentId, frame: &[u8]) {
    let mut transport = connect_agent(config, identity).await;
    send_agent_frame(config, identity, &mut transport, frame).await;
}

/// Sends an ordered batch during one on-demand connection, then closes it.
pub async fn send_on_demand_frames(config: &AgentConfig, identity: AgentId, frames: &[&[u8]]) {
    let mut transport = connect_agent(config, identity).await;
    for frame in frames {
        send_agent_frame(config, identity, &mut transport, frame).await;
    }
}

/// Loads an Agent without exposing key material through command-line arguments or logs.
pub fn load_agent(config: &AgentConfig) -> Result<Agent, Box<dyn std::error::Error>> {
    let id = AgentId(decode_hex::<16>(&config.agent_id)?);
    let keys = AgentKeys::from_seeds(
        read_hex_file(&config.ed25519_secret_file)?,
        read_hex_file(&config.x25519_secret_file)?,
    );
    let ca = CaPublicKeys {
        ed25519: read_hex_file(&config.ca_ed25519_public_file)?,
        x25519: read_hex_file(&config.ca_x25519_public_file)?,
    };
    Ok(Agent::new(id, keys, ca))
}

/// Reads a fixed-size hexadecimal value, accepting surrounding whitespace only.
pub fn read_hex_file<const N: usize>(
    path: impl AsRef<Path>,
) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let value = fs::read_to_string(path)?;
    decode_hex(value.trim())
}

/// Decodes a fixed-size hexadecimal value.
pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| "incorrect hexadecimal value length".into())
}

/// Current Unix timestamp used by replay protection.
pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_hex_round_trip_and_validation() {
        let text = "20000000000000000000000000000003";
        let decoded = decode_hex::<16>(text).expect("valid test identity");
        assert_eq!(hex::encode(decoded), text);
        assert!(decode_hex::<16>("20").is_err());
        assert!(decode_hex::<16>("zz000000000000000000000000000000").is_err());
        assert_ne!(decoded.as_slice(), text.as_bytes());
    }
}
