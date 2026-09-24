#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Certificate Authority protocol engine, bounded stores, and replay protection.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use protocol_core::{
    AgentId, AttributeId, CryptoRandom, EnvironmentRef, Error, HEADER_LEN, HandlerId,
    MAX_ATTRIBUTE_BYTES, MAX_FRAME_LEN, MessageType, OneShotSecret, OperationRef, SessionId,
    TypeId, ValueRef, encode_response, open_in_place, parse_envelope, parse_operation,
    seal_in_place, verify_envelope_signature,
};
use x25519_dalek::StaticSecret;

/// Maximum provisioned agents in the in-memory implementation.
pub const DEFAULT_MAX_AGENTS: usize = 1024;
/// Maximum environments in the in-memory implementation.
pub const DEFAULT_MAX_ENVIRONMENTS: usize = 1024;
/// Maximum active subscriptions.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 4096;
/// Default replay entries.
pub const DEFAULT_MAX_REPLAYS: usize = 16_384;

/// Provisioned public keys for one Agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeys {
    /// Ed25519 key used to verify requests.
    pub ed25519: [u8; 32],
    /// Static X25519 key used for encrypted deliveries.
    pub x25519: [u8; 32],
}

/// Public-key directory; provisioning is an authenticated out-of-band action.
pub trait KeyDirectory: Send + Sync {
    /// Fetches a provisioned Agent.
    fn keys(&self, agent: AgentId) -> Result<PublicKeys, Error>;
    /// Adds/replaces a provisioned Agent key pair.
    fn provision(&self, agent: AgentId, keys: PublicKeys) -> Result<(), Error>;
}

/// Environment storage with atomic whole-environment replacement.
pub trait EnvironmentStore: Send + Sync {
    /// Loads a canonical encoded environment operation.
    fn environment(&self, agent: AgentId) -> Result<Option<Vec<u8>>, Error>;
    /// Atomically replaces an environment.
    fn set_environment(&self, agent: AgentId, encoded: Vec<u8>) -> Result<(), Error>;
}

/// Lifetime of a stored subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionKind {
    /// Consumed atomically by the first authorized matching publication.
    OneShot,
    /// Retained for every authorized matching publication.
    Permanent,
}

/// Stored subscription, including the canonical encoded predicate operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSubscription {
    /// Subscriber.
    pub subscriber: AgentId,
    /// Type index.
    pub type_id: TypeId,
    /// Delivery handler.
    pub handler: HandlerId,
    /// Whether the subscription is consumed after its first match.
    pub kind: SubscriptionKind,
    /// Canonical subscribe operation.
    pub encoded: Vec<u8>,
}

/// Subscription storage indexed by publication type.
pub trait SubscriptionStore: Send + Sync {
    /// Upserts by `(subscriber, type, handler)`.
    fn put_subscription(&self, subscription: StoredSubscription) -> Result<(), Error>;
    /// Returns a stable snapshot so locks are not held during crypto.
    fn subscriptions_for(&self, type_id: TypeId) -> Result<Vec<StoredSubscription>, Error>;
    /// Atomically claims a matching subscription before a delivery is generated.
    ///
    /// A one-shot entry is removed; a permanent entry is only checked for continued existence.
    fn claim_subscription(&self, subscription: &StoredSubscription) -> Result<bool, Error>;
}

/// Atomic replay state.
pub trait ReplayStore: Send + Sync {
    /// Marks a verified session once, or rejects it.
    fn check_and_mark(
        &self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error>;
}

/// Store bundle used by the CA engine.
pub trait CaStore: KeyDirectory + EnvironmentStore + SubscriptionStore + ReplayStore {}

impl<T> CaStore for T where T: KeyDirectory + EnvironmentStore + SubscriptionStore + ReplayStore {}

/// Bounded, concurrent in-memory store. No locks escape a method call.
pub struct MemoryStore {
    keys: RwLock<BTreeMap<AgentId, PublicKeys>>,
    environments: RwLock<BTreeMap<AgentId, Vec<u8>>>,
    subscriptions: RwLock<BTreeMap<TypeId, Vec<StoredSubscription>>>,
    replay: Mutex<ReplayCache>,
    limits: StoreLimits,
}

/// Explicit store limits.
#[derive(Clone, Copy, Debug)]
pub struct StoreLimits {
    /// Provisioned Agent count.
    pub agents: usize,
    /// Environment count.
    pub environments: usize,
    /// Total subscription count.
    pub subscriptions: usize,
    /// Replay entry count.
    pub replays: usize,
    /// Replay TTL in seconds.
    pub replay_ttl_seconds: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            agents: DEFAULT_MAX_AGENTS,
            environments: DEFAULT_MAX_ENVIRONMENTS,
            subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
            replays: DEFAULT_MAX_REPLAYS,
            replay_ttl_seconds: 600,
        }
    }
}

impl MemoryStore {
    /// Creates an empty bounded store.
    pub fn new(limits: StoreLimits) -> Self {
        Self {
            keys: RwLock::new(BTreeMap::new()),
            environments: RwLock::new(BTreeMap::new()),
            subscriptions: RwLock::new(BTreeMap::new()),
            replay: Mutex::new(ReplayCache::new(limits.replays, limits.replay_ttl_seconds)),
            limits,
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(StoreLimits::default())
    }
}

impl KeyDirectory for MemoryStore {
    fn keys(&self, agent: AgentId) -> Result<PublicKeys, Error> {
        self.keys
            .read()
            .get(&agent)
            .copied()
            .ok_or(Error::BadSignature)
    }

    fn provision(&self, agent: AgentId, keys: PublicKeys) -> Result<(), Error> {
        if agent == AgentId::CA {
            return Err(Error::Malformed);
        }
        let mut directory = self.keys.write();
        if !directory.contains_key(&agent) && directory.len() >= self.limits.agents {
            return Err(Error::Capacity);
        }
        directory.insert(agent, keys);
        Ok(())
    }
}

impl EnvironmentStore for MemoryStore {
    fn environment(&self, agent: AgentId) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.environments.read().get(&agent).cloned())
    }

    fn set_environment(&self, agent: AgentId, encoded: Vec<u8>) -> Result<(), Error> {
        let mut environments = self.environments.write();
        if !environments.contains_key(&agent) && environments.len() >= self.limits.environments {
            return Err(Error::Capacity);
        }
        environments.insert(agent, encoded);
        Ok(())
    }
}

impl SubscriptionStore for MemoryStore {
    fn put_subscription(&self, subscription: StoredSubscription) -> Result<(), Error> {
        let mut subscriptions = self.subscriptions.write();
        let count: usize = subscriptions.values().map(Vec::len).sum();
        let bucket = subscriptions.entry(subscription.type_id).or_default();
        if let Some(existing) = bucket.iter_mut().find(|entry| {
            entry.subscriber == subscription.subscriber && entry.handler == subscription.handler
        }) {
            *existing = subscription;
            return Ok(());
        }
        if count >= self.limits.subscriptions {
            return Err(Error::Capacity);
        }
        bucket.push(subscription);
        bucket.sort_by_key(|entry| (entry.subscriber, entry.handler));
        Ok(())
    }

    fn subscriptions_for(&self, type_id: TypeId) -> Result<Vec<StoredSubscription>, Error> {
        Ok(self
            .subscriptions
            .read()
            .get(&type_id)
            .cloned()
            .unwrap_or_default())
    }

    fn claim_subscription(&self, subscription: &StoredSubscription) -> Result<bool, Error> {
        let mut subscriptions = self.subscriptions.write();
        let Some(bucket) = subscriptions.get_mut(&subscription.type_id) else {
            return Ok(false);
        };
        let Some(index) = bucket.iter().position(|entry| entry == subscription) else {
            return Ok(false);
        };
        if subscription.kind == SubscriptionKind::OneShot {
            bucket.remove(index);
        }
        Ok(true)
    }
}

impl ReplayStore for MemoryStore {
    fn check_and_mark(
        &self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error> {
        self.replay
            .lock()
            .check_and_mark(sender, session, now_seconds)
    }
}

/// Bounded deterministic replay cache. Capacity exhaustion fails closed.
#[derive(Clone)]
pub struct ReplayCache {
    entries: BTreeMap<(AgentId, SessionId), u64>,
    maximum: usize,
    ttl_seconds: u64,
}

impl ReplayCache {
    /// Creates an empty cache.
    pub const fn new(maximum: usize, ttl_seconds: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            maximum,
            ttl_seconds,
        }
    }

    /// Checks and marks one session.
    pub fn check_and_mark(
        &mut self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error> {
        self.entries.retain(|_, expires| *expires > now_seconds);
        if self.entries.contains_key(&(sender, session)) {
            return Err(Error::Replay);
        }
        if self.entries.len() >= self.maximum {
            return Err(Error::Capacity);
        }
        let expires = now_seconds.saturating_add(self.ttl_seconds);
        self.entries.insert((sender, session), expires);
        Ok(())
    }
}

impl protocol_core::ReplayProtector for ReplayCache {
    fn check_and_mark(
        &mut self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error> {
        Self::check_and_mark(self, sender, session, now_seconds)
    }
}

/// CA long-term keys. Private values are never exposed by `Debug` or logs.
pub struct CaKeys {
    signing: SigningKey,
    x25519: StaticSecret,
}

/// Runtime type of an environment attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeType {
    /// Boolean attribute.
    Bool,
    /// Signed 64-bit integer attribute.
    I64,
    /// Bounded byte-string attribute.
    Bytes,
}

impl AttributeType {
    fn matches(self, value: ValueRef<'_>) -> bool {
        matches!(
            (self, value),
            (Self::Bool, ValueRef::Bool(_))
                | (Self::I64, ValueRef::I64(_))
                | (Self::Bytes, ValueRef::Bytes(_))
        )
    }
}

/// Authority allowed to establish an attribute value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeAuthority {
    /// The authenticated Agent may change the attribute itself.
    SelfDeclared,
    /// The value must have been approved out of band by the CA.
    CaIssued,
}

/// Owned attribute value used in static policy configuration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttributeValue {
    /// Boolean value.
    Bool(bool),
    /// Signed 64-bit integer value.
    I64(i64),
    /// Bounded byte string.
    Bytes(Vec<u8>),
}

impl AttributeValue {
    /// Creates a bounded byte-string policy value.
    pub fn bytes(value: impl AsRef<[u8]>) -> Result<Self, EnvironmentPolicyError> {
        let value = value.as_ref();
        if value.len() > MAX_ATTRIBUTE_BYTES {
            return Err(EnvironmentPolicyError::InvalidConfiguration);
        }
        Ok(Self::Bytes(value.to_vec()))
    }

    /// Returns the runtime type of the value.
    pub const fn attribute_type(&self) -> AttributeType {
        match self {
            Self::Bool(_) => AttributeType::Bool,
            Self::I64(_) => AttributeType::I64,
            Self::Bytes(_) => AttributeType::Bytes,
        }
    }

    fn matches_ref(&self, other: ValueRef<'_>) -> bool {
        match (self, other) {
            (Self::Bool(left), ValueRef::Bool(right)) => *left == right,
            (Self::I64(left), ValueRef::I64(right)) => *left == right,
            (Self::Bytes(left), ValueRef::Bytes(right)) => left.as_slice() == right,
            _ => false,
        }
    }
}

/// Non-sensitive reason for policy rejection or invalid policy setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentPolicyError {
    /// An attribute is not part of the configured schema.
    UnknownAttribute,
    /// An attribute has the wrong runtime type.
    WrongAttributeType,
    /// A CA-issued claim is absent, altered, or not approved for this identity.
    CaApprovalRequired,
    /// The value is outside the configured allow-list.
    ValueNotAllowed,
    /// The static policy itself is inconsistent or exceeds protocol bounds.
    InvalidConfiguration,
}

impl core::fmt::Display for EnvironmentPolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for EnvironmentPolicyError {}

/// CA policy applied before a complete environment replacement is stored.
///
/// Attributes that participate in authorization decisions must be CA-approved. Implementations
/// may also impose delivery-domain boundaries independently of publisher and subscriber
/// predicates, which makes isolation fail closed even for empty predicates.
pub trait EnvironmentPolicy: Send + Sync {
    /// Validates a proposed environment for an authenticated Agent.
    fn validate_environment(
        &self,
        agent: AgentId,
        current: Option<EnvironmentRef<'_>>,
        proposed: EnvironmentRef<'_>,
    ) -> Result<(), EnvironmentPolicyError>;

    /// Applies mandatory domain isolation after both application predicates match.
    fn allows_delivery(
        &self,
        _type_id: TypeId,
        _publisher: EnvironmentRef<'_>,
        _subscriber: EnvironmentRef<'_>,
    ) -> bool {
        true
    }

    /// Revalidates both stored environments and applies delivery constraints as one decision.
    ///
    /// Implementations with reloadable state must use one consistent policy snapshot for all
    /// three checks. The default is appropriate for immutable policies.
    fn authorize_delivery(
        &self,
        publisher_id: AgentId,
        publisher: EnvironmentRef<'_>,
        subscriber_id: AgentId,
        subscriber: EnvironmentRef<'_>,
        type_id: TypeId,
    ) -> bool {
        self.validate_environment(publisher_id, None, publisher)
            .is_ok()
            && self
                .validate_environment(subscriber_id, None, subscriber)
                .is_ok()
            && self.allows_delivery(type_id, publisher, subscriber)
    }
}

/// Compatibility policy that accepts every structurally valid environment.
///
/// New applications must use an explicit policy instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAllEnvironmentPolicy;

impl EnvironmentPolicy for AllowAllEnvironmentPolicy {
    fn validate_environment(
        &self,
        _agent: AgentId,
        _current: Option<EnvironmentRef<'_>>,
        _proposed: EnvironmentRef<'_>,
    ) -> Result<(), EnvironmentPolicyError> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct AttributeRule {
    attribute_type: AttributeType,
    authority: AttributeAuthority,
}

/// Declarative bounded-environment policy for demos, integration tests, and small deployments.
///
/// CA-issued values are approved per identity. Optional value allow-lists constrain enums such as
/// roles, tenants, swarms, and capabilities. Type-specific isolation attributes are compared by
/// the CA before delivery and cannot be bypassed with an empty predicate.
#[derive(Clone, Default)]
pub struct StaticEnvironmentPolicy {
    rules: BTreeMap<AttributeId, AttributeRule>,
    allowed_values: BTreeMap<AttributeId, Vec<AttributeValue>>,
    approvals: BTreeMap<(AgentId, AttributeId), AttributeValue>,
    isolation: BTreeMap<TypeId, Vec<AttributeId>>,
    subscriber_requirements: BTreeMap<(TypeId, AttributeId), Vec<AttributeValue>>,
}

/// Atomically replaceable policy used by long-running CA processes.
///
/// A complete candidate is parsed and validated before [`replace`](Self::replace) takes the
/// write lock, so request processing observes either the old policy or the new policy, never a
/// partially updated set of rules.
#[derive(Clone)]
pub struct DynamicEnvironmentPolicy {
    inner: std::sync::Arc<RwLock<StaticEnvironmentPolicy>>,
}

impl DynamicEnvironmentPolicy {
    /// Creates a reloadable policy from a fully validated snapshot.
    pub fn new(policy: StaticEnvironmentPolicy) -> Self {
        Self {
            inner: std::sync::Arc::new(RwLock::new(policy)),
        }
    }

    /// Atomically publishes a complete new policy snapshot.
    pub fn replace(&self, policy: StaticEnvironmentPolicy) {
        *self.inner.write() = policy;
    }
}

impl EnvironmentPolicy for DynamicEnvironmentPolicy {
    fn validate_environment(
        &self,
        agent: AgentId,
        current: Option<EnvironmentRef<'_>>,
        proposed: EnvironmentRef<'_>,
    ) -> Result<(), EnvironmentPolicyError> {
        self.inner
            .read()
            .validate_environment(agent, current, proposed)
    }

    fn allows_delivery(
        &self,
        type_id: TypeId,
        publisher: EnvironmentRef<'_>,
        subscriber: EnvironmentRef<'_>,
    ) -> bool {
        self.inner
            .read()
            .allows_delivery(type_id, publisher, subscriber)
    }

    fn authorize_delivery(
        &self,
        publisher_id: AgentId,
        publisher: EnvironmentRef<'_>,
        subscriber_id: AgentId,
        subscriber: EnvironmentRef<'_>,
        type_id: TypeId,
    ) -> bool {
        let policy = self.inner.read();
        policy
            .validate_environment(publisher_id, None, publisher)
            .is_ok()
            && policy
                .validate_environment(subscriber_id, None, subscriber)
                .is_ok()
            && policy.allows_delivery(type_id, publisher, subscriber)
    }
}

impl StaticEnvironmentPolicy {
    /// Creates an empty deny-by-default policy.
    pub const fn new() -> Self {
        Self {
            rules: BTreeMap::new(),
            allowed_values: BTreeMap::new(),
            approvals: BTreeMap::new(),
            isolation: BTreeMap::new(),
            subscriber_requirements: BTreeMap::new(),
        }
    }

    /// Registers a self-declarable attribute and its required runtime type.
    pub fn register_self_declared(
        &mut self,
        attribute: AttributeId,
        attribute_type: AttributeType,
    ) -> Result<(), EnvironmentPolicyError> {
        self.register_rule(attribute, attribute_type, AttributeAuthority::SelfDeclared)
    }

    /// Registers a CA-issued attribute and its required runtime type.
    pub fn register_ca_issued(
        &mut self,
        attribute: AttributeId,
        attribute_type: AttributeType,
    ) -> Result<(), EnvironmentPolicyError> {
        self.register_rule(attribute, attribute_type, AttributeAuthority::CaIssued)
    }

    fn register_rule(
        &mut self,
        attribute: AttributeId,
        attribute_type: AttributeType,
        authority: AttributeAuthority,
    ) -> Result<(), EnvironmentPolicyError> {
        if let Some(existing) = self.rules.get(&attribute) {
            if existing.attribute_type != attribute_type || existing.authority != authority {
                return Err(EnvironmentPolicyError::InvalidConfiguration);
            }
            return Ok(());
        }
        self.rules.insert(
            attribute,
            AttributeRule {
                attribute_type,
                authority,
            },
        );
        Ok(())
    }

    /// Adds an admitted value for an attribute. No entries means any value of the right type.
    pub fn allow_value(
        &mut self,
        attribute: AttributeId,
        value: AttributeValue,
    ) -> Result<(), EnvironmentPolicyError> {
        let rule = self
            .rules
            .get(&attribute)
            .ok_or(EnvironmentPolicyError::InvalidConfiguration)?;
        if rule.attribute_type != value.attribute_type() {
            return Err(EnvironmentPolicyError::InvalidConfiguration);
        }
        let values = self.allowed_values.entry(attribute).or_default();
        if !values.contains(&value) {
            values.push(value);
        }
        Ok(())
    }

    /// Approves one exact CA-issued value for an authenticated identity.
    pub fn approve(
        &mut self,
        agent: AgentId,
        attribute: AttributeId,
        value: AttributeValue,
    ) -> Result<(), EnvironmentPolicyError> {
        let rule = self
            .rules
            .get(&attribute)
            .ok_or(EnvironmentPolicyError::InvalidConfiguration)?;
        if rule.authority != AttributeAuthority::CaIssued {
            return Err(EnvironmentPolicyError::InvalidConfiguration);
        }
        self.validate_configured_value(attribute, &value)?;
        self.approvals.insert((agent, attribute), value);
        Ok(())
    }

    /// Requires equality of the listed environment attributes for one publication type.
    pub fn isolate(
        &mut self,
        type_id: TypeId,
        attributes: &[AttributeId],
    ) -> Result<(), EnvironmentPolicyError> {
        if attributes.is_empty() || attributes.len() > protocol_core::MAX_CLAUSES {
            return Err(EnvironmentPolicyError::InvalidConfiguration);
        }
        for attribute in attributes {
            let rule = self
                .rules
                .get(attribute)
                .ok_or(EnvironmentPolicyError::InvalidConfiguration)?;
            if rule.authority != AttributeAuthority::CaIssued {
                return Err(EnvironmentPolicyError::InvalidConfiguration);
            }
        }
        self.isolation.insert(type_id, attributes.to_vec());
        Ok(())
    }

    /// Admits one subscriber attribute value for a publication type.
    ///
    /// Multiple calls for the same type and attribute form an allow-list. Different attributes
    /// are conjunctive. The attribute must be CA-issued, so a subscriber cannot grant itself the
    /// required role or clearance category.
    pub fn allow_subscriber_value(
        &mut self,
        type_id: TypeId,
        attribute: AttributeId,
        value: AttributeValue,
    ) -> Result<(), EnvironmentPolicyError> {
        let rule = self
            .rules
            .get(&attribute)
            .ok_or(EnvironmentPolicyError::InvalidConfiguration)?;
        if rule.authority != AttributeAuthority::CaIssued
            || rule.attribute_type != value.attribute_type()
        {
            return Err(EnvironmentPolicyError::InvalidConfiguration);
        }
        self.validate_configured_value(attribute, &value)?;
        let values = self
            .subscriber_requirements
            .entry((type_id, attribute))
            .or_default();
        if !values.contains(&value) {
            values.push(value);
        }
        Ok(())
    }

    fn validate_configured_value(
        &self,
        attribute: AttributeId,
        value: &AttributeValue,
    ) -> Result<(), EnvironmentPolicyError> {
        let rule = self
            .rules
            .get(&attribute)
            .ok_or(EnvironmentPolicyError::InvalidConfiguration)?;
        if rule.attribute_type != value.attribute_type() {
            return Err(EnvironmentPolicyError::InvalidConfiguration);
        }
        if let Some(values) = self.allowed_values.get(&attribute)
            && !values.is_empty()
            && !values.contains(value)
        {
            return Err(EnvironmentPolicyError::ValueNotAllowed);
        }
        Ok(())
    }
}

impl EnvironmentPolicy for StaticEnvironmentPolicy {
    fn validate_environment(
        &self,
        agent: AgentId,
        _current: Option<EnvironmentRef<'_>>,
        proposed: EnvironmentRef<'_>,
    ) -> Result<(), EnvironmentPolicyError> {
        for attribute in proposed.iter() {
            let rule = self
                .rules
                .get(&attribute.id)
                .ok_or(EnvironmentPolicyError::UnknownAttribute)?;
            if !rule.attribute_type.matches(attribute.value) {
                return Err(EnvironmentPolicyError::WrongAttributeType);
            }
            if let Some(allowed) = self.allowed_values.get(&attribute.id)
                && !allowed.is_empty()
                && !allowed
                    .iter()
                    .any(|value| value.matches_ref(attribute.value))
            {
                return Err(EnvironmentPolicyError::ValueNotAllowed);
            }
            if rule.authority == AttributeAuthority::CaIssued
                && !self
                    .approvals
                    .get(&(agent, attribute.id))
                    .is_some_and(|approved| approved.matches_ref(attribute.value))
            {
                return Err(EnvironmentPolicyError::CaApprovalRequired);
            }
        }
        for ((approved_agent, attribute), value) in &self.approvals {
            if *approved_agent == agent
                && !proposed
                    .get(*attribute)
                    .is_some_and(|candidate| value.matches_ref(candidate))
            {
                return Err(EnvironmentPolicyError::CaApprovalRequired);
            }
        }
        Ok(())
    }

    fn allows_delivery(
        &self,
        type_id: TypeId,
        publisher: EnvironmentRef<'_>,
        subscriber: EnvironmentRef<'_>,
    ) -> bool {
        let isolated = self.isolation.get(&type_id).is_none_or(|attributes| {
            attributes.iter().all(|attribute| {
                publisher
                    .get(*attribute)
                    .zip(subscriber.get(*attribute))
                    .is_some_and(|(left, right)| left == right)
            })
        });
        isolated
            && self
                .subscriber_requirements
                .iter()
                .filter(|((required_type, _), _)| *required_type == type_id)
                .all(|((_, attribute), values)| {
                    subscriber.get(*attribute).is_some_and(|candidate| {
                        values.iter().any(|value| value.matches_ref(candidate))
                    })
                })
    }
}

impl CaKeys {
    /// Loads independently provisioned signing and key-agreement secrets.
    pub fn from_seeds(ed25519_seed: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&ed25519_seed),
            x25519: StaticSecret::from(x25519_secret),
        }
    }

    /// Ed25519 trust anchor.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Static X25519 CA public key.
    pub fn x25519_public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.x25519).to_bytes()
    }
}

/// Result of one CA request.
#[derive(Debug)]
pub enum ProcessResult {
    /// State update accepted; no delivery produced.
    Accepted,
    /// One separately encrypted frame per authorized subscriber.
    Deliveries(Vec<Vec<u8>>),
}

/// Protocol CA over replaceable storage adapters.
pub struct CertificateAuthority<S, P = AllowAllEnvironmentPolicy> {
    keys: CaKeys,
    store: S,
    policy: P,
}

impl<S: CaStore> CertificateAuthority<S, AllowAllEnvironmentPolicy> {
    /// Constructs a compatibility CA without application attribute restrictions.
    ///
    /// New applications should call [`CertificateAuthority::with_policy`].
    pub const fn new(keys: CaKeys, store: S) -> Self {
        Self {
            keys,
            store,
            policy: AllowAllEnvironmentPolicy,
        }
    }
}

impl<S: CaStore, P: EnvironmentPolicy> CertificateAuthority<S, P> {
    /// Constructs a CA with an explicit deny-by-default environment policy.
    pub const fn with_policy(keys: CaKeys, store: S, policy: P) -> Self {
        Self {
            keys,
            store,
            policy,
        }
    }

    /// Accesses the store for authenticated provisioning/inspection.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// CA public Ed25519 key.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.keys.verifying_key()
    }

    /// CA public static X25519 key.
    pub fn x25519_public(&self) -> [u8; 32] {
        self.keys.x25519_public()
    }

    /// Authenticates, replay-checks, decrypts, authorizes, and processes one request.
    pub fn process(
        &self,
        frame: &mut [u8],
        now_seconds: u64,
        rng: &mut impl CryptoRandom,
    ) -> Result<ProcessResult, Error> {
        let (sender, message_type, handler, session) = {
            let envelope = parse_envelope(frame)?;
            if envelope.recipient != AgentId::CA || envelope.sender == AgentId::CA {
                return Err(Error::WrongRecipient);
            }
            if envelope.message_type == MessageType::PublicationResponse {
                return Err(Error::WrongMessageType);
            }
            (
                envelope.sender,
                envelope.message_type,
                envelope.handler,
                envelope.session_id,
            )
        };
        let public_keys = self.store.keys(sender)?;
        let verifying =
            VerifyingKey::from_bytes(&public_keys.ed25519).map_err(|_| Error::BadSignature)?;
        {
            let envelope = parse_envelope(frame)?;
            verify_envelope_signature(&envelope, &verifying)?;
        }
        self.store.check_and_mark(sender, session, now_seconds)?;
        let plaintext = open_in_place(
            frame,
            AgentId::CA,
            message_type,
            &verifying,
            &self.keys.x25519,
        )?;
        let operation = parse_operation(plaintext)?;
        match (message_type, operation) {
            (MessageType::SetEnvironment, OperationRef::SetEnvironment(proposed)) => {
                if handler != HandlerId::NONE {
                    return Err(Error::WrongHandler);
                }
                let current = self.store.environment(sender)?;
                let current = current
                    .as_deref()
                    .map(parse_operation)
                    .transpose()?
                    .map(|operation| match operation {
                        OperationRef::SetEnvironment(environment) => Ok(environment),
                        _ => Err(Error::Malformed),
                    })
                    .transpose()?;
                self.policy
                    .validate_environment(sender, current, proposed)
                    .map_err(|_| Error::UnauthorizedEnvironment)?;
                self.store.set_environment(sender, plaintext.to_vec())?;
                Ok(ProcessResult::Accepted)
            }
            (MessageType::Subscribe, OperationRef::Subscribe { type_id, .. }) => {
                if handler == HandlerId::NONE {
                    return Err(Error::WrongHandler);
                }
                self.validate_stored_environment(sender)?;
                self.store.put_subscription(StoredSubscription {
                    subscriber: sender,
                    type_id,
                    handler,
                    kind: SubscriptionKind::OneShot,
                    encoded: plaintext.to_vec(),
                })?;
                Ok(ProcessResult::Accepted)
            }
            (MessageType::SubscribePermanent, OperationRef::SubscribePermanent { type_id, .. }) => {
                if handler == HandlerId::NONE {
                    return Err(Error::WrongHandler);
                }
                self.validate_stored_environment(sender)?;
                self.store.put_subscription(StoredSubscription {
                    subscriber: sender,
                    type_id,
                    handler,
                    kind: SubscriptionKind::Permanent,
                    encoded: plaintext.to_vec(),
                })?;
                Ok(ProcessResult::Accepted)
            }
            (
                MessageType::Publish,
                OperationRef::Publish {
                    type_id,
                    predicate,
                    value,
                },
            ) => {
                if handler != HandlerId::NONE {
                    return Err(Error::WrongHandler);
                }
                let publisher_environment =
                    self.store.environment(sender)?.ok_or(Error::Malformed)?;
                let publisher_environment = match parse_operation(&publisher_environment)? {
                    OperationRef::SetEnvironment(environment) => environment,
                    _ => return Err(Error::Malformed),
                };
                self.policy
                    .validate_environment(sender, None, publisher_environment)
                    .map_err(|_| Error::UnauthorizedEnvironment)?;
                let subscriptions = self.store.subscriptions_for(type_id)?;
                let value = value.to_vec();
                let mut deliveries = Vec::new();
                for subscription in subscriptions {
                    let subscription_predicate =
                        match (subscription.kind, parse_operation(&subscription.encoded)?) {
                            (
                                SubscriptionKind::OneShot,
                                OperationRef::Subscribe {
                                    type_id: stored_type,
                                    predicate,
                                },
                            ) if stored_type == type_id => predicate,
                            (
                                SubscriptionKind::Permanent,
                                OperationRef::SubscribePermanent {
                                    type_id: stored_type,
                                    predicate,
                                },
                            ) if stored_type == type_id => predicate,
                            _ => return Err(Error::Malformed),
                        };
                    if !subscription_predicate.evaluate(publisher_environment) {
                        continue;
                    }
                    let Some(subscriber_environment) =
                        self.store.environment(subscription.subscriber)?
                    else {
                        continue;
                    };
                    let subscriber_environment = match parse_operation(&subscriber_environment)? {
                        OperationRef::SetEnvironment(environment) => environment,
                        _ => return Err(Error::Malformed),
                    };
                    if !predicate.evaluate(subscriber_environment) {
                        continue;
                    }
                    if !self.policy.authorize_delivery(
                        sender,
                        publisher_environment,
                        subscription.subscriber,
                        subscriber_environment,
                        type_id,
                    ) {
                        continue;
                    }
                    let recipient_keys = self.store.keys(subscription.subscriber)?;
                    let delivery = self.delivery(
                        sender,
                        subscription.subscriber,
                        subscription.handler,
                        type_id,
                        &value,
                        &recipient_keys.x25519,
                        rng,
                    )?;
                    if !self.store.claim_subscription(&subscription)? {
                        continue;
                    }
                    deliveries.push(delivery);
                }
                Ok(ProcessResult::Deliveries(deliveries))
            }
            _ => Err(Error::WrongMessageType),
        }
    }

    fn validate_stored_environment(&self, agent: AgentId) -> Result<(), Error> {
        let encoded = self
            .store
            .environment(agent)?
            .ok_or(Error::UnauthorizedEnvironment)?;
        let environment = match parse_operation(&encoded)? {
            OperationRef::SetEnvironment(environment) => environment,
            _ => return Err(Error::Malformed),
        };
        self.policy
            .validate_environment(agent, None, environment)
            .map_err(|_| Error::UnauthorizedEnvironment)
    }

    #[allow(clippy::too_many_arguments)]
    fn delivery(
        &self,
        publisher: AgentId,
        recipient: AgentId,
        handler: HandlerId,
        type_id: TypeId,
        value: &[u8],
        recipient_x25519: &[u8; 32],
        rng: &mut impl CryptoRandom,
    ) -> Result<Vec<u8>, Error> {
        let mut frame = vec![0u8; MAX_FRAME_LEN];
        let plaintext_len = encode_response(&mut frame[HEADER_LEN..], type_id, publisher, value)?;
        let mut session = [0u8; 16];
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut session);
        rng.fill_bytes(&mut salt);
        let length = seal_in_place(
            &mut frame,
            plaintext_len,
            MessageType::PublicationResponse,
            AgentId::CA,
            recipient,
            handler,
            SessionId(session),
            salt,
            OneShotSecret::generate(rng),
            recipient_x25519,
            &self.keys.signing,
        )?;
        frame.truncate(length);
        Ok(frame)
    }
}

/// Minimal persistent public/state snapshot adapter using atomic rename.
///
/// The snapshot includes public keys, environments, subscriptions, and replay entries, but never
/// CA private keys. Deployments should place it on an encrypted filesystem. The in-memory store
/// is published only after the complete replacement file is durably committed.
pub struct SnapshotFile {
    path: PathBuf,
    lock: Mutex<()>,
}

impl SnapshotFile {
    /// Creates a snapshot writer rooted at an explicit path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// Atomically persists already-canonical bounded state bytes.
    pub fn commit(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(Error::Oversized);
        }
        let _guard = self.lock.lock();
        let temporary = temporary_path(&self.path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|_| Error::Capacity)?;
        file.write_all(bytes).map_err(|_| Error::Capacity)?;
        file.sync_all().map_err(|_| Error::Capacity)?;
        fs::rename(&temporary, &self.path).map_err(|_| Error::Capacity)?;
        if let Some(parent) = self.path.parent()
            && let Ok(directory) = OpenOptions::new().read(true).open(parent)
        {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    /// Reads a bounded snapshot.
    pub fn load(&self) -> Result<Option<Vec<u8>>, Error> {
        match fs::read(&self.path) {
            Ok(bytes) if bytes.len() <= 16 * 1024 * 1024 => Ok(Some(bytes)),
            Ok(_) => Err(Error::Oversized),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Capacity),
        }
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

#[derive(Clone)]
struct PersistentState {
    keys: BTreeMap<AgentId, PublicKeys>,
    environments: BTreeMap<AgentId, Vec<u8>>,
    subscriptions: BTreeMap<TypeId, Vec<StoredSubscription>>,
    replay: ReplayCache,
}

/// Transactional file-backed CA store for the demo daemons and small deployments.
///
/// Each mutation clones the bounded state, validates it, writes a mode-0600 snapshot with
/// `fsync`, then atomically publishes the new in-memory state. This favors crash consistency and
/// simple review over high write throughput. Larger deployments should implement the same four
/// store traits using a transactional database.
pub struct PersistentStore {
    state: Mutex<PersistentState>,
    transaction: Mutex<()>,
    snapshot: SnapshotFile,
    limits: StoreLimits,
}

impl PersistentStore {
    /// Opens or creates a bounded store and validates the complete existing snapshot.
    pub fn open(path: impl Into<PathBuf>, limits: StoreLimits) -> Result<Self, Error> {
        let snapshot = SnapshotFile::new(path);
        let state = match snapshot.load()? {
            Some(bytes) => decode_state(&bytes, limits)?,
            None => PersistentState {
                keys: BTreeMap::new(),
                environments: BTreeMap::new(),
                subscriptions: BTreeMap::new(),
                replay: ReplayCache::new(limits.replays, limits.replay_ttl_seconds),
            },
        };
        Ok(Self {
            state: Mutex::new(state),
            transaction: Mutex::new(()),
            snapshot,
            limits,
        })
    }

    fn commit(&self, next: PersistentState) -> Result<(), Error> {
        let encoded = encode_state(&next)?;
        self.snapshot.commit(&encoded)?;
        *self.state.lock() = next;
        Ok(())
    }

    /// Atomically makes the persistent key directory exactly match `configured`.
    ///
    /// Removed identities, and identities whose keys rotate, lose their environment,
    /// subscriptions, and replay entries in the same durable snapshot. The complete candidate is
    /// validated and persisted before it becomes visible in memory.
    pub fn reconcile_agents(&self, configured: &[(AgentId, PublicKeys)]) -> Result<(), Error> {
        if configured.len() > self.limits.agents {
            return Err(Error::Capacity);
        }
        let mut keys = BTreeMap::new();
        for (agent, public_keys) in configured {
            if *agent == AgentId::CA || keys.insert(*agent, *public_keys).is_some() {
                return Err(Error::Malformed);
            }
        }

        let _transaction = self.transaction.lock();
        let mut next = self.state.lock().clone();
        let previous_keys = next.keys.clone();
        let unchanged = |agent: &AgentId| {
            previous_keys
                .get(agent)
                .zip(keys.get(agent))
                .is_some_and(|(old, new)| old == new)
        };
        next.environments.retain(|agent, _| unchanged(agent));
        for subscriptions in next.subscriptions.values_mut() {
            subscriptions.retain(|subscription| unchanged(&subscription.subscriber));
        }
        next.subscriptions
            .retain(|_, subscriptions| !subscriptions.is_empty());
        next.replay.entries.retain(|(agent, _), _| unchanged(agent));
        next.keys = keys;
        self.commit(next)
    }
}

impl KeyDirectory for PersistentStore {
    fn keys(&self, agent: AgentId) -> Result<PublicKeys, Error> {
        self.state
            .lock()
            .keys
            .get(&agent)
            .copied()
            .ok_or(Error::BadSignature)
    }

    fn provision(&self, agent: AgentId, keys: PublicKeys) -> Result<(), Error> {
        if agent == AgentId::CA {
            return Err(Error::Malformed);
        }
        let _transaction = self.transaction.lock();
        let mut next = self.state.lock().clone();
        if !next.keys.contains_key(&agent) && next.keys.len() >= self.limits.agents {
            return Err(Error::Capacity);
        }
        next.keys.insert(agent, keys);
        self.commit(next)
    }
}

impl EnvironmentStore for PersistentStore {
    fn environment(&self, agent: AgentId) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.state.lock().environments.get(&agent).cloned())
    }

    fn set_environment(&self, agent: AgentId, encoded: Vec<u8>) -> Result<(), Error> {
        if !matches!(
            parse_operation(&encoded),
            Ok(OperationRef::SetEnvironment(_))
        ) {
            return Err(Error::Malformed);
        }
        let _transaction = self.transaction.lock();
        let mut next = self.state.lock().clone();
        if !next.environments.contains_key(&agent)
            && next.environments.len() >= self.limits.environments
        {
            return Err(Error::Capacity);
        }
        next.environments.insert(agent, encoded);
        self.commit(next)
    }
}

impl SubscriptionStore for PersistentStore {
    fn put_subscription(&self, subscription: StoredSubscription) -> Result<(), Error> {
        let valid = matches!(
            (subscription.kind, parse_operation(&subscription.encoded)),
            (SubscriptionKind::OneShot, Ok(OperationRef::Subscribe { type_id, .. }))
                | (
                    SubscriptionKind::Permanent,
                    Ok(OperationRef::SubscribePermanent { type_id, .. })
                ) if type_id == subscription.type_id
        );
        if !valid {
            return Err(Error::Malformed);
        }
        let _transaction = self.transaction.lock();
        let mut next = self.state.lock().clone();
        let count: usize = next.subscriptions.values().map(Vec::len).sum();
        let bucket = next.subscriptions.entry(subscription.type_id).or_default();
        if let Some(existing) = bucket.iter_mut().find(|entry| {
            entry.subscriber == subscription.subscriber && entry.handler == subscription.handler
        }) {
            *existing = subscription;
        } else {
            if count >= self.limits.subscriptions {
                return Err(Error::Capacity);
            }
            bucket.push(subscription);
            bucket.sort_by_key(|entry| (entry.subscriber, entry.handler));
        }
        self.commit(next)
    }

    fn subscriptions_for(&self, type_id: TypeId) -> Result<Vec<StoredSubscription>, Error> {
        Ok(self
            .state
            .lock()
            .subscriptions
            .get(&type_id)
            .cloned()
            .unwrap_or_default())
    }

    fn claim_subscription(&self, subscription: &StoredSubscription) -> Result<bool, Error> {
        if subscription.kind == SubscriptionKind::Permanent {
            return Ok(self
                .state
                .lock()
                .subscriptions
                .get(&subscription.type_id)
                .is_some_and(|bucket| bucket.contains(subscription)));
        }
        let _transaction = self.transaction.lock();
        let mut next = self.state.lock().clone();
        let Some(bucket) = next.subscriptions.get_mut(&subscription.type_id) else {
            return Ok(false);
        };
        let Some(index) = bucket.iter().position(|entry| entry == subscription) else {
            return Ok(false);
        };
        bucket.remove(index);
        self.commit(next)?;
        Ok(true)
    }
}

impl ReplayStore for PersistentStore {
    fn check_and_mark(
        &self,
        sender: AgentId,
        session: SessionId,
        now_seconds: u64,
    ) -> Result<(), Error> {
        let _transaction = self.transaction.lock();
        let mut next = self.state.lock().clone();
        next.replay.check_and_mark(sender, session, now_seconds)?;
        self.commit(next)
    }
}

const STATE_MAGIC: &[u8; 8] = b"SPSTATE1";

fn encode_state(state: &PersistentState) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    output.extend_from_slice(STATE_MAGIC);
    push_u32(&mut output, state.keys.len())?;
    for (agent, keys) in &state.keys {
        output.extend_from_slice(&agent.0);
        output.extend_from_slice(&keys.ed25519);
        output.extend_from_slice(&keys.x25519);
    }
    push_u32(&mut output, state.environments.len())?;
    for (agent, encoded) in &state.environments {
        output.extend_from_slice(&agent.0);
        push_bytes(&mut output, encoded)?;
    }
    let subscription_count: usize = state.subscriptions.values().map(Vec::len).sum();
    push_u32(&mut output, subscription_count)?;
    for subscriptions in state.subscriptions.values() {
        for subscription in subscriptions {
            output.extend_from_slice(&subscription.subscriber.0);
            output.extend_from_slice(&subscription.type_id.0.to_be_bytes());
            output.extend_from_slice(&subscription.handler.0);
            push_bytes(&mut output, &subscription.encoded)?;
        }
    }
    push_u32(&mut output, state.replay.entries.len())?;
    for ((sender, session), expires) in &state.replay.entries {
        output.extend_from_slice(&sender.0);
        output.extend_from_slice(&session.0);
        output.extend_from_slice(&expires.to_be_bytes());
    }
    Ok(output)
}

fn decode_state(input: &[u8], limits: StoreLimits) -> Result<PersistentState, Error> {
    let mut cursor = StateCursor { input, position: 0 };
    if cursor.take(8)? != STATE_MAGIC {
        return Err(Error::Malformed);
    }
    let key_count = cursor.count(limits.agents)?;
    let mut keys = BTreeMap::new();
    for _ in 0..key_count {
        let agent = AgentId(cursor.array()?);
        if agent == AgentId::CA
            || keys
                .insert(
                    agent,
                    PublicKeys {
                        ed25519: cursor.array()?,
                        x25519: cursor.array()?,
                    },
                )
                .is_some()
        {
            return Err(Error::Malformed);
        }
    }
    let environment_count = cursor.count(limits.environments)?;
    let mut environments = BTreeMap::new();
    for _ in 0..environment_count {
        let agent = AgentId(cursor.array()?);
        let encoded = cursor.bytes(protocol_core::MAX_PLAINTEXT_LEN)?.to_vec();
        if !matches!(
            parse_operation(&encoded),
            Ok(OperationRef::SetEnvironment(_))
        ) || environments.insert(agent, encoded).is_some()
        {
            return Err(Error::Malformed);
        }
    }
    let subscription_count = cursor.count(limits.subscriptions)?;
    let mut subscriptions: BTreeMap<TypeId, Vec<StoredSubscription>> = BTreeMap::new();
    for _ in 0..subscription_count {
        let subscriber = AgentId(cursor.array()?);
        let type_id = TypeId(u32::from_be_bytes(cursor.array()?));
        let handler = HandlerId(cursor.array()?);
        let encoded = cursor.bytes(protocol_core::MAX_PLAINTEXT_LEN)?.to_vec();
        let kind = match parse_operation(&encoded) {
            Ok(OperationRef::Subscribe {
                type_id: parsed, ..
            }) if parsed == type_id => SubscriptionKind::OneShot,
            Ok(OperationRef::SubscribePermanent {
                type_id: parsed, ..
            }) if parsed == type_id => SubscriptionKind::Permanent,
            _ => return Err(Error::Malformed),
        };
        if handler == HandlerId::NONE {
            return Err(Error::Malformed);
        }
        subscriptions
            .entry(type_id)
            .or_default()
            .push(StoredSubscription {
                subscriber,
                type_id,
                handler,
                kind,
                encoded,
            });
    }
    let replay_count = cursor.count(limits.replays)?;
    let mut replay = ReplayCache::new(limits.replays, limits.replay_ttl_seconds);
    for _ in 0..replay_count {
        let key = (AgentId(cursor.array()?), SessionId(cursor.array()?));
        let expires = u64::from_be_bytes(cursor.array()?);
        if replay.entries.insert(key, expires).is_some() {
            return Err(Error::Malformed);
        }
    }
    if cursor.position != input.len() {
        return Err(Error::Malformed);
    }
    Ok(PersistentState {
        keys,
        environments,
        subscriptions,
        replay,
    })
}

fn push_u32(output: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| Error::Oversized)?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    push_u32(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

struct StateCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> StateCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Malformed)?;
        let value = self.input.get(self.position..end).ok_or(Error::Malformed)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }

    fn count(&mut self, maximum: usize) -> Result<usize, Error> {
        let value = u32::from_be_bytes(self.array()?) as usize;
        if value > maximum {
            Err(Error::Capacity)
        } else {
            Ok(value)
        }
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = self.count(maximum)?;
        self.take(length)
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use protocol_core::{AttributeRef, ValueRef, encode_environment};

    fn parsed_environment<'a>(
        bytes: &'a mut [u8],
        attributes: &[AttributeRef<'_>],
    ) -> EnvironmentRef<'a> {
        let length = encode_environment(bytes, attributes).unwrap_or(0);
        match parse_operation(&bytes[..length]) {
            Ok(OperationRef::SetEnvironment(environment)) => environment,
            _ => unreachable!(),
        }
    }

    #[test]
    fn static_policy_binds_privileged_claims_to_identity_and_type() {
        let agent = AgentId([7; 16]);
        let tenant = AttributeId(1);
        let health = AttributeId(2);
        let mut policy = StaticEnvironmentPolicy::new();
        assert!(
            policy
                .register_ca_issued(tenant, AttributeType::Bytes)
                .is_ok()
        );
        assert!(
            policy
                .register_self_declared(health, AttributeType::Bool)
                .is_ok()
        );
        assert!(
            policy
                .approve(
                    agent,
                    tenant,
                    AttributeValue::bytes(b"approved").unwrap_or(AttributeValue::Bytes(Vec::new())),
                )
                .is_ok()
        );

        let mut valid_bytes = [0u8; 64];
        let valid = parsed_environment(
            &mut valid_bytes,
            &[
                AttributeRef {
                    id: tenant,
                    value: ValueRef::Bytes(b"approved"),
                },
                AttributeRef {
                    id: health,
                    value: ValueRef::Bool(true),
                },
            ],
        );
        assert_eq!(policy.validate_environment(agent, None, valid), Ok(()));

        let mut forged_bytes = [0u8; 64];
        let forged = parsed_environment(
            &mut forged_bytes,
            &[AttributeRef {
                id: tenant,
                value: ValueRef::Bytes(b"forged"),
            }],
        );
        assert_eq!(
            policy.validate_environment(agent, Some(valid), forged),
            Err(EnvironmentPolicyError::CaApprovalRequired)
        );

        let mut mistyped_bytes = [0u8; 64];
        let mistyped = parsed_environment(
            &mut mistyped_bytes,
            &[
                AttributeRef {
                    id: tenant,
                    value: ValueRef::Bytes(b"approved"),
                },
                AttributeRef {
                    id: health,
                    value: ValueRef::I64(1),
                },
            ],
        );
        assert_eq!(
            policy.validate_environment(agent, Some(valid), mistyped),
            Err(EnvironmentPolicyError::WrongAttributeType)
        );
    }

    #[test]
    fn static_policy_mandatory_isolation_fails_closed() {
        let tenant = AttributeId(1);
        let type_id = TypeId(9);
        let mut policy = StaticEnvironmentPolicy::new();
        assert!(
            policy
                .register_ca_issued(tenant, AttributeType::Bytes)
                .is_ok()
        );
        assert!(policy.isolate(type_id, &[tenant]).is_ok());
        let mut publisher_bytes = [0u8; 32];
        let publisher = parsed_environment(
            &mut publisher_bytes,
            &[AttributeRef {
                id: tenant,
                value: ValueRef::Bytes(b"a"),
            }],
        );
        let mut subscriber_bytes = [0u8; 32];
        let subscriber = parsed_environment(
            &mut subscriber_bytes,
            &[AttributeRef {
                id: tenant,
                value: ValueRef::Bytes(b"b"),
            }],
        );
        assert!(!policy.allows_delivery(type_id, publisher, subscriber));
    }

    #[test]
    fn dynamic_policy_replaces_a_complete_snapshot() {
        let agent = AgentId([8; 16]);
        let attribute = AttributeId(3);
        let mut first = StaticEnvironmentPolicy::new();
        assert!(
            first
                .register_self_declared(attribute, AttributeType::Bool)
                .is_ok()
        );
        let dynamic = DynamicEnvironmentPolicy::new(first);
        let mut bytes = [0u8; 32];
        let environment = parsed_environment(
            &mut bytes,
            &[AttributeRef {
                id: attribute,
                value: ValueRef::Bool(true),
            }],
        );
        assert_eq!(
            dynamic.validate_environment(agent, None, environment),
            Ok(())
        );

        let second = StaticEnvironmentPolicy::new();
        dynamic.replace(second);
        assert_eq!(
            dynamic.validate_environment(agent, None, environment),
            Err(EnvironmentPolicyError::UnknownAttribute)
        );
    }
}
