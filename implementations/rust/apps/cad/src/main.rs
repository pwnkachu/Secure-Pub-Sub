#![forbid(unsafe_code)]

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use app_common::{decode_hex, read_hex_file, unix_seconds};
use ca_core::{
    AttributeType, AttributeValue, CaKeys, CertificateAuthority, DynamicEnvironmentPolicy,
    PersistentStore, ProcessResult, PublicKeys, StaticEnvironmentPolicy, StoreLimits,
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use infrastructure_link::{
    DedupWindow, FrameKind, LinkError, MessageId, PendingFrames, decode, encode,
    verify_authentication,
};
use protocol_core::{AgentId, AttributeId, TypeId};
use serde::Deserialize;
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use transport::SystemRandom;

#[derive(Parser)]
#[command(about = "SecurePubSub configurable Certificate Authority daemon")]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: SocketAddr,
    state: PathBuf,
    ca_ed25519_secret_file: PathBuf,
    ca_x25519_secret_file: PathBuf,
    broker_link_psk_file: PathBuf,
    #[serde(default = "default_auth_timeout_seconds")]
    broker_auth_timeout_seconds: u64,
    #[serde(default = "default_link_io_timeout_seconds")]
    broker_link_io_timeout_seconds: u64,
    #[serde(default = "default_link_retry_seconds")]
    broker_link_retry_seconds: u64,
    #[serde(default = "default_pending_deliveries")]
    broker_pending_deliveries: usize,
    #[serde(default = "default_dedup_entries")]
    broker_dedup_entries: usize,
    #[serde(default)]
    limits: Limits,
    agents: Vec<AgentEntry>,
    policy: PolicyConfig,
    #[serde(default = "default_reload_seconds")]
    reload_seconds: u64,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    agents: Option<usize>,
    environments: Option<usize>,
    subscriptions: Option<usize>,
    replays: Option<usize>,
    replay_ttl_seconds: Option<u64>,
}

impl Limits {
    fn resolve(&self) -> StoreLimits {
        let defaults = StoreLimits::default();
        StoreLimits {
            agents: self.agents.unwrap_or(defaults.agents),
            environments: self.environments.unwrap_or(defaults.environments),
            subscriptions: self.subscriptions.unwrap_or(defaults.subscriptions),
            replays: self.replays.unwrap_or(defaults.replays),
            replay_ttl_seconds: self
                .replay_ttl_seconds
                .unwrap_or(defaults.replay_ttl_seconds),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEntry {
    id: String,
    ed25519_public_file: PathBuf,
    x25519_public_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    attributes: Vec<AttributeRule>,
    #[serde(default)]
    approvals: Vec<Approval>,
    isolations: Vec<Isolation>,
    #[serde(default)]
    subscriber_requirements: Vec<SubscriberRequirement>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttributeRule {
    id: u16,
    kind: Kind,
    authority: Authority,
    #[serde(default)]
    allowed: Vec<ConfiguredValue>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Bool,
    I64,
    Bytes,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Authority {
    SelfDeclared,
    CaIssued,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ConfiguredValue {
    Bool(bool),
    I64(i64),
    Bytes(String),
    Hex(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    agent: String,
    attribute: u16,
    value: ConfiguredValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Isolation {
    type_id: u32,
    attributes: Vec<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriberRequirement {
    type_id: u32,
    attribute: u16,
    values: Vec<ConfiguredValue>,
}

fn default_reload_seconds() -> u64 {
    2
}

const fn default_auth_timeout_seconds() -> u64 {
    5
}
const fn default_link_io_timeout_seconds() -> u64 {
    10
}
const fn default_link_retry_seconds() -> u64 {
    2
}
const fn default_pending_deliveries() -> usize {
    4096
}
const fn default_dedup_entries() -> usize {
    8192
}

fn load(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn value(value: &ConfiguredValue) -> Result<AttributeValue, Box<dyn std::error::Error>> {
    Ok(match value {
        ConfiguredValue::Bool(value) => AttributeValue::Bool(*value),
        ConfiguredValue::I64(value) => AttributeValue::I64(*value),
        ConfiguredValue::Bytes(value) => AttributeValue::bytes(value.as_bytes())?,
        ConfiguredValue::Hex(value) => AttributeValue::bytes(hex::decode(value)?)?,
    })
}

fn configured_agents(
    config: &Config,
) -> Result<Vec<(AgentId, PublicKeys)>, Box<dyn std::error::Error>> {
    config
        .agents
        .iter()
        .map(|entry| {
            Ok((
                AgentId(decode_hex(&entry.id)?),
                PublicKeys {
                    ed25519: read_hex_file(&entry.ed25519_public_file)?,
                    x25519: read_hex_file(&entry.x25519_public_file)?,
                },
            ))
        })
        .collect()
}

fn build_policy(
    config: &PolicyConfig,
) -> Result<StaticEnvironmentPolicy, Box<dyn std::error::Error>> {
    let mut policy = StaticEnvironmentPolicy::new();
    for rule in &config.attributes {
        let kind = match rule.kind {
            Kind::Bool => AttributeType::Bool,
            Kind::I64 => AttributeType::I64,
            Kind::Bytes => AttributeType::Bytes,
        };
        match rule.authority {
            Authority::SelfDeclared => policy.register_self_declared(AttributeId(rule.id), kind)?,
            Authority::CaIssued => policy.register_ca_issued(AttributeId(rule.id), kind)?,
        }
        for allowed in &rule.allowed {
            policy.allow_value(AttributeId(rule.id), value(allowed)?)?;
        }
    }
    for approval in &config.approvals {
        policy.approve(
            AgentId(decode_hex(&approval.agent)?),
            AttributeId(approval.attribute),
            value(&approval.value)?,
        )?;
    }
    for isolation in &config.isolations {
        let attributes: Vec<_> = isolation
            .attributes
            .iter()
            .copied()
            .map(AttributeId)
            .collect();
        policy.isolate(TypeId(isolation.type_id), &attributes)?;
    }
    for requirement in &config.subscriber_requirements {
        for allowed in &requirement.values {
            policy.allow_subscriber_value(
                TypeId(requirement.type_id),
                AttributeId(requirement.attribute),
                value(allowed)?,
            )?;
        }
    }
    Ok(policy)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load(&args.config)?;
    let limits = config.limits.resolve();
    if config.broker_pending_deliveries < limits.subscriptions {
        return Err("broker_pending_deliveries must cover the maximum subscription count".into());
    }
    let broker_psk = read_hex_file(&config.broker_link_psk_file)?;
    let store = PersistentStore::open(&config.state, limits)?;
    store.reconcile_agents(&configured_agents(&config)?)?;
    let dynamic = DynamicEnvironmentPolicy::new(build_policy(&config.policy)?);
    let ca = CertificateAuthority::with_policy(
        CaKeys::from_seeds(
            read_hex_file(&config.ca_ed25519_secret_file)?,
            read_hex_file(&config.ca_x25519_secret_file)?,
        ),
        store,
        dynamic.clone(),
    );
    let listener = TcpListener::bind(config.listen).await?;
    let bound_address = listener.local_addr()?;
    let mut rng = SystemRandom::new()?;
    let reload_period = Duration::from_secs(config.reload_seconds.max(1));
    let mut reload = tokio::time::interval(reload_period);
    let auth_deadline = Duration::from_secs(config.broker_auth_timeout_seconds.max(1));
    let io_deadline = Duration::from_secs(config.broker_link_io_timeout_seconds.max(1));
    let retry_period = Duration::from_secs(config.broker_link_retry_seconds.max(1));
    let mut pending_deliveries = PendingFrames::new(config.broker_pending_deliveries);
    let mut acquired_requests = DedupWindow::new(config.broker_dedup_entries);
    let mut current_request = None;
    println!("cad ready listening on {bound_address}");
    loop {
        // Deployment invariant: only this accepted broker link is serviced. A second TCP
        // connection may wait in the OS backlog but is not accepted until this one closes.
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let mut framed = Framed::new(stream, infrastructure_link::codec());
        if let Err(error) = authenticate_broker(&mut framed, &broker_psk, auth_deadline).await {
            eprintln!("cad event=broker-authentication-rejected peer={peer} reason={error}");
            continue;
        }
        println!("cad event=broker-connected peer={peer}");
        let mut disconnected = false;
        for frame in pending_deliveries.snapshot() {
            if send_link_frame(&mut framed, frame, io_deadline)
                .await
                .is_err()
            {
                disconnected = true;
                break;
            }
        }
        if disconnected {
            eprintln!("cad event=broker-disconnected peer={peer}");
            continue;
        }
        let mut retry = tokio::time::interval(retry_period);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        retry.tick().await;
        loop {
            tokio::select! {
                incoming = framed.next() => {
                    let Some(Ok(bytes)) = incoming else { break };
                    let Ok(link_frame) = decode(&bytes) else { break };
                    match link_frame.kind {
                        FrameKind::Ack => {
                            pending_deliveries.acknowledge(link_frame.id);
                            if pending_deliveries.is_empty()
                                && let Some(request_id) = current_request.take()
                            {
                                let ack = encode(FrameKind::Ack, request_id, &[])?;
                                if send_link_frame(&mut framed, ack, io_deadline).await.is_err() { break; }
                            }
                        }
                        FrameKind::Request if current_request == Some(link_frame.id) => {
                            // Its delivery group is still pending; the retry timer resends it.
                        }
                        FrameKind::Request if acquired_requests.contains(link_frame.id) => {
                            let ack = encode(FrameKind::Ack, link_frame.id, &[])?;
                            if send_link_frame(&mut framed, ack, io_deadline).await.is_err() { break; }
                        }
                        FrameKind::Request if current_request.is_none() => {
                            let request_id = link_frame.id;
                            let mut envelope = link_frame.payload.to_vec();
                            match ca.process(&mut envelope, unix_seconds(), &mut rng) {
                                Ok(ProcessResult::Accepted) => {
                                    acquired_requests.insert(request_id)?;
                                    let ack = encode(FrameKind::Ack, request_id, &[])?;
                                    if send_link_frame(&mut framed, ack, io_deadline).await.is_err() { break; }
                                    println!("cad event=request-accepted");
                                }
                                Ok(ProcessResult::Deliveries(deliveries)) => {
                                    let count = deliveries.len();
                                    if deliveries.len() > pending_deliveries.remaining() {
                                        eprintln!("cad event=delivery-queue-rejected queue=ca-delivery reason=QueueFull");
                                        break;
                                    }
                                    let mut encoded_deliveries = Vec::with_capacity(deliveries.len());
                                    for delivery in deliveries {
                                        let id = random_link_id()?;
                                        let encoded = encode(FrameKind::Delivery, id, &delivery)?;
                                        pending_deliveries.insert(id, encoded.clone())?;
                                        encoded_deliveries.push(encoded);
                                    }
                                    acquired_requests.insert(request_id)?;
                                    if encoded_deliveries.is_empty() {
                                        let ack = encode(FrameKind::Ack, request_id, &[])?;
                                        if send_link_frame(&mut framed, ack, io_deadline).await.is_err() { break; }
                                    } else {
                                        current_request = Some(request_id);
                                        for delivery in encoded_deliveries {
                                            if send_link_frame(&mut framed, delivery, io_deadline).await.is_err() {
                                                disconnected = true;
                                                break;
                                            }
                                        }
                                        if disconnected { break; }
                                    }
                                    println!("cad event=publication-accepted recipients={count}");
                                }
                                Err(error) => {
                                    acquired_requests.insert(request_id)?;
                                    let ack = encode(FrameKind::Ack, request_id, &[])?;
                                    if send_link_frame(&mut framed, ack, io_deadline).await.is_err() { break; }
                                    eprintln!("cad event=request-rejected reason={error:?}");
                                }
                            }
                        }
                        _ => break,
                    }
                }
                _ = retry.tick(), if !pending_deliveries.is_empty() => {
                    for frame in pending_deliveries.snapshot() {
                        if send_link_frame(&mut framed, frame, io_deadline).await.is_err() {
                            disconnected = true;
                            break;
                        }
                    }
                    if disconnected { break; }
                }
                _ = reload.tick() => {
                    let candidate = load(&args.config).and_then(|candidate| {
                        let policy = build_policy(&candidate.policy)?;
                        let agents = configured_agents(&candidate)?;
                        Ok((policy, agents))
                    });
                    match candidate {
                        Ok((policy, agents)) => match ca.store().reconcile_agents(&agents) {
                            Ok(()) => {
                                dynamic.replace(policy);
                                println!("cad event=configuration-reloaded");
                            }
                            Err(error) => eprintln!("cad event=configuration-reload-rejected reason={error:?}"),
                        },
                        Err(error) => eprintln!("cad event=policy-reload-rejected reason={error}"),
                    }
                }
            }
        }
        eprintln!("cad event=broker-disconnected peer={peer}");
    }
}

fn random_link_id() -> Result<MessageId, LinkError> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| LinkError::Authentication)?;
    Ok(MessageId(id))
}

async fn authenticate_broker(
    framed: &mut Framed<TcpStream, LengthDelimitedCodec>,
    psk: &[u8; 32],
    deadline: Duration,
) -> Result<(), LinkError> {
    let challenge = random_link_id()?;
    let mut challenge_bytes = [0; 32];
    getrandom::fill(&mut challenge_bytes).map_err(|_| LinkError::Authentication)?;
    let encoded = encode(FrameKind::AuthChallenge, challenge, &challenge_bytes)?;
    send_link_frame(framed, encoded, deadline).await?;
    let response = timeout(deadline, framed.next())
        .await
        .map_err(|_| LinkError::Authentication)?
        .ok_or(LinkError::Authentication)?
        .map_err(|_| LinkError::Authentication)?;
    let response = decode(&response)?;
    if response.kind != FrameKind::AuthResponse || response.id != challenge {
        return Err(LinkError::Authentication);
    }
    verify_authentication(psk, &challenge_bytes, response.payload)?;
    send_link_frame(framed, encode(FrameKind::AuthOk, challenge, &[])?, deadline).await
}

async fn send_link_frame(
    framed: &mut Framed<TcpStream, LengthDelimitedCodec>,
    frame: Vec<u8>,
    deadline: Duration,
) -> Result<(), LinkError> {
    timeout(deadline, framed.send(frame.into()))
        .await
        .map_err(|_| LinkError::InvalidFrame)?
        .map_err(|_| LinkError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_hex_is_binary_and_strict() {
        let parsed: ConfiguredValue =
            serde_json::from_str(r#"{"kind":"hex","value":"20000000000000000000000000000003"}"#)
                .expect("valid test JSON");
        assert_eq!(
            value(&parsed).expect("valid binary identity"),
            AttributeValue::Bytes([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3].to_vec())
        );
        let malformed: ConfiguredValue =
            serde_json::from_str(r#"{"kind":"hex","value":"not-hex"}"#)
                .expect("valid JSON with invalid hex value");
        assert!(value(&malformed).is_err());
    }
}
