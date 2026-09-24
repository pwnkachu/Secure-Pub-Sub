#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Bounded honest-but-curious Broker routing core.
//!
//! Agent sockets and the infrastructure CA link are deliberately different
//! resources. Agent deliveries may wait in bounded, in-memory FIFO queues;
//! requests for the CA use one dedicated bounded channel consumed by the CA
//! connection manager.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::{Mutex, RwLock};
use protocol_core::{AgentId, Error, MessageType, parse_envelope};
use tokio::sync::mpsc::{self, error::TrySendError};

/// Maximum default concurrent Agent identities.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default per-online-Agent backpressure queue.
pub const DEFAULT_QUEUE_DEPTH: usize = 64;
/// Default per-Agent offline FIFO capacity.
pub const DEFAULT_OFFLINE_QUEUE_DEPTH: usize = 64;
/// Default Agent-to-CA queue capacity while the CA link is unavailable.
pub const DEFAULT_CA_QUEUE_DEPTH: usize = 256;

/// Observable routing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    /// The envelope was malformed or violated a protocol routing rule.
    Protocol(Error),
    /// The reserved CA identity was presented on the public Agent listener.
    ReservedIdentity,
    /// This identity already has an active socket.
    DuplicateConnection,
    /// The configured number of active Agent identities was reached.
    ConnectionLimit,
    /// The bounded queue feeding the CA link was full or unavailable.
    CaQueueFull,
    /// A connected Agent's bounded delivery queue was full.
    OnlineQueueFull,
    /// A disconnected Agent's bounded delivery queue was full.
    OfflineQueueFull,
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RouteError {}

impl From<Error> for RouteError {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}

struct Connection {
    generation: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

#[derive(Default)]
struct State {
    connections: BTreeMap<AgentId, Connection>,
}

/// Bounded storage abstraction for deliveries addressed to disconnected Agents.
///
/// Implementations may persist data, but must preserve per-Agent FIFO order and
/// fail closed before exceeding their configured bounds.
pub trait OfflineQueueStore: Send + Sync {
    /// Appends one delivery, returning `OfflineQueueFull` if it was not acquired.
    fn enqueue(&self, identity: AgentId, frame: Vec<u8>) -> Result<(), RouteError>;
    /// Atomically takes the complete FIFO for a reconnecting Agent.
    fn take(&self, identity: AgentId) -> VecDeque<Vec<u8>>;
    /// Prepends older unsent deliveries ahead of anything concurrently stored.
    fn prepend(&self, identity: AgentId, frames: VecDeque<Vec<u8>>) -> Result<(), RouteError>;
    /// Current queued delivery count for one Agent.
    fn len(&self, identity: AgentId) -> usize;
}

/// Bounded in-memory offline queue storage used by the reference broker.
pub struct MemoryOfflineQueueStore {
    depth: usize,
    queues: Mutex<BTreeMap<AgentId, VecDeque<Vec<u8>>>>,
}

impl MemoryOfflineQueueStore {
    /// Creates empty per-Agent FIFOs with the given capacity.
    pub const fn new(depth: usize) -> Self {
        Self {
            depth,
            queues: Mutex::new(BTreeMap::new()),
        }
    }
}

impl OfflineQueueStore for MemoryOfflineQueueStore {
    fn enqueue(&self, identity: AgentId, frame: Vec<u8>) -> Result<(), RouteError> {
        let mut queues = self.queues.lock();
        if self.depth == 0 {
            return Err(RouteError::OfflineQueueFull);
        }
        let queue = queues.entry(identity).or_default();
        if queue.len() >= self.depth {
            return Err(RouteError::OfflineQueueFull);
        }
        queue.push_back(frame);
        Ok(())
    }

    fn take(&self, identity: AgentId) -> VecDeque<Vec<u8>> {
        self.queues.lock().remove(&identity).unwrap_or_default()
    }

    fn prepend(&self, identity: AgentId, mut frames: VecDeque<Vec<u8>>) -> Result<(), RouteError> {
        let mut queues = self.queues.lock();
        frames.append(&mut queues.remove(&identity).unwrap_or_default());
        let overflowed = frames.len() > self.depth;
        frames.truncate(self.depth);
        if !frames.is_empty() {
            queues.insert(identity, frames);
        }
        if overflowed {
            Err(RouteError::OfflineQueueFull)
        } else {
            Ok(())
        }
    }

    fn len(&self, identity: AgentId) -> usize {
        self.queues.lock().get(&identity).map_or(0, VecDeque::len)
    }
}

/// One active Agent registration.
pub struct AgentRegistration {
    identity: AgentId,
    generation: u64,
    pending: VecDeque<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
}

impl AgentRegistration {
    /// Declared Agent identity.
    pub const fn identity(&self) -> AgentId {
        self.identity
    }

    /// Unique token used to make stale cleanup harmless.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Removes the next FIFO delivery for best-effort TCP transmission.
    ///
    /// A failed write is requeued by `brokerd`; a successful kernel write is
    /// considered delivered because the public Agent link has no application ACK.
    pub async fn recv_best_effort(&mut self) -> Option<Vec<u8>> {
        if let Some(frame) = self.pending.pop_front() {
            Some(frame)
        } else {
            self.receiver.recv().await
        }
    }

    /// Number of deliveries captured while the Agent was offline.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Tries to remove one pending or live delivery without waiting.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.pending
            .pop_front()
            .or_else(|| self.receiver.try_recv().ok())
    }
}

/// Concurrent bounded opaque-envelope router.
#[derive(Clone)]
pub struct BrokerRouter {
    state: Arc<RwLock<State>>,
    maximum: usize,
    online_depth: usize,
    offline: Arc<dyn OfflineQueueStore>,
    ca_depth: usize,
    generation: Arc<AtomicU64>,
    ca_sender: mpsc::Sender<Vec<u8>>,
    ca_receiver: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
}

impl BrokerRouter {
    /// Creates a router using the same capacity for online and offline Agent queues.
    pub fn new(maximum: usize, queue_depth: usize) -> Self {
        Self::with_limits(maximum, queue_depth, queue_depth, DEFAULT_CA_QUEUE_DEPTH)
    }

    /// Creates a router with independent explicit bounds.
    pub fn with_limits(
        maximum: usize,
        online_depth: usize,
        offline_depth: usize,
        ca_queue_depth: usize,
    ) -> Self {
        Self::with_offline_store(
            maximum,
            online_depth,
            ca_queue_depth,
            Arc::new(MemoryOfflineQueueStore::new(offline_depth)),
        )
    }

    /// Creates a router using a caller-supplied bounded offline queue store.
    pub fn with_offline_store(
        maximum: usize,
        online_depth: usize,
        ca_queue_depth: usize,
        offline: Arc<dyn OfflineQueueStore>,
    ) -> Self {
        let (ca_sender, ca_receiver) = mpsc::channel(ca_queue_depth.max(1));
        Self {
            state: Arc::new(RwLock::new(State::default())),
            maximum,
            online_depth,
            offline,
            ca_depth: ca_queue_depth,
            generation: Arc::new(AtomicU64::new(1)),
            ca_sender,
            ca_receiver: Arc::new(Mutex::new(Some(ca_receiver))),
        }
    }

    /// Takes the sole request receiver for the dedicated Broker--CA link.
    pub fn take_ca_requests(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.ca_receiver.lock().take()
    }

    /// Registers one public Agent socket and atomically captures its offline FIFO.
    pub fn register(&self, identity: AgentId) -> Result<AgentRegistration, RouteError> {
        if identity == AgentId::CA {
            return Err(RouteError::ReservedIdentity);
        }
        if self.maximum == 0 || self.online_depth == 0 {
            return Err(RouteError::ConnectionLimit);
        }
        let mut state = self.state.write();
        if state.connections.contains_key(&identity) {
            return Err(RouteError::DuplicateConnection);
        }
        if state.connections.len() >= self.maximum {
            return Err(RouteError::ConnectionLimit);
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(self.online_depth);
        state
            .connections
            .insert(identity, Connection { generation, sender });
        let pending = self.offline.take(identity);
        Ok(AgentRegistration {
            identity,
            generation,
            pending,
            receiver,
        })
    }

    /// Removes a registration only when both identity and generation match.
    pub fn unregister(&self, identity: AgentId, generation: u64) {
        let mut state = self.state.write();
        if state
            .connections
            .get(&identity)
            .is_some_and(|connection| connection.generation == generation)
        {
            state.connections.remove(&identity);
        }
    }

    /// Atomically removes a connection and returns all unsent delivery frames
    /// to the front of its offline FIFO.
    pub fn disconnect_and_requeue(
        &self,
        registration: &mut AgentRegistration,
        first: Option<Vec<u8>>,
    ) -> Result<(), RouteError> {
        let mut unsent = VecDeque::new();
        if let Some(frame) = first {
            unsent.push_back(frame);
        }
        let mut state = self.state.write();
        if !state
            .connections
            .get(&registration.identity)
            .is_some_and(|connection| connection.generation == registration.generation)
        {
            return Ok(());
        }
        state.connections.remove(&registration.identity);
        while let Some(frame) = registration.try_recv() {
            unsent.push_back(frame);
        }
        self.offline.prepend(registration.identity, unsent)
    }

    /// Routes an Agent request to the dedicated CA connection manager.
    pub fn route_agent_request(
        &self,
        connection_identity: AgentId,
        frame: Vec<u8>,
    ) -> Result<(), RouteError> {
        let envelope = parse_envelope(&frame)?;
        if envelope.sender != connection_identity {
            return Err(RouteError::Protocol(Error::BadSignature));
        }
        match envelope.message_type {
            MessageType::SetEnvironment
            | MessageType::Subscribe
            | MessageType::SubscribePermanent
            | MessageType::Publish
                if envelope.sender != AgentId::CA && envelope.recipient == AgentId::CA => {}
            _ => return Err(RouteError::Protocol(Error::WrongMessageType)),
        }
        if self.ca_depth == 0 {
            return Err(RouteError::CaQueueFull);
        }
        self.ca_sender
            .try_send(frame)
            .map_err(|_| RouteError::CaQueueFull)
    }

    /// Routes a CA delivery to a live Agent or its bounded in-memory offline FIFO.
    pub fn route_ca_delivery(&self, frame: Vec<u8>) -> Result<(), RouteError> {
        let recipient = {
            let envelope = parse_envelope(&frame)?;
            if envelope.sender != AgentId::CA
                || envelope.recipient == AgentId::CA
                || envelope.message_type != MessageType::PublicationResponse
            {
                return Err(RouteError::Protocol(Error::WrongMessageType));
            }
            envelope.recipient
        };

        let mut state = self.state.write();
        let frame = if let Some(connection) = state.connections.get(&recipient) {
            match connection.sender.try_send(frame) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(_)) => return Err(RouteError::OnlineQueueFull),
                Err(TrySendError::Closed(error)) => {
                    let frame = error;
                    state.connections.remove(&recipient);
                    frame
                }
            }
        } else {
            frame
        };
        drop(state);
        self.offline.enqueue(recipient, frame)
    }

    /// Compatibility dispatcher for callers that already distinguish the source identity.
    pub async fn route(
        &self,
        connection_identity: AgentId,
        frame: Vec<u8>,
    ) -> Result<(), RouteError> {
        if connection_identity == AgentId::CA {
            self.route_ca_delivery(frame)
        } else {
            self.route_agent_request(connection_identity, frame)
        }
    }

    /// Current connected Agent count (the CA link is never included).
    pub fn connection_count(&self) -> usize {
        self.state.read().connections.len()
    }

    /// Current offline queue length for an Agent.
    pub fn offline_len(&self, identity: AgentId) -> usize {
        self.offline.len(identity)
    }
}

impl Default for BrokerRouter {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_CONNECTIONS,
            DEFAULT_QUEUE_DEPTH,
            DEFAULT_OFFLINE_QUEUE_DEPTH,
            DEFAULT_CA_QUEUE_DEPTH,
        )
    }
}

#[cfg(test)]
mod tests {
    use protocol_core::{HEADER_LEN, HandlerId, SIGNATURE_LEN, SessionId, TAG_LEN, encode_header};

    use super::*;

    const AGENT: AgentId = AgentId([1; 16]);

    fn frame(kind: MessageType, sender: AgentId, recipient: AgentId, marker: u8) -> Vec<u8> {
        let mut output = vec![0; HEADER_LEN + TAG_LEN + SIGNATURE_LEN];
        encode_header(
            &mut output,
            kind,
            sender,
            recipient,
            HandlerId([marker; 16]),
            SessionId([marker; 16]),
            &[marker; 32],
            &[marker; 32],
            0,
        )
        .expect("test header");
        output
    }

    #[test]
    fn ca_is_not_a_public_agent_and_duplicates_are_rejected() {
        let router = BrokerRouter::new(2, 2);
        assert!(matches!(
            router.register(AgentId::CA),
            Err(RouteError::ReservedIdentity)
        ));
        let registration = router.register(AGENT).expect("first connection");
        assert!(matches!(
            router.register(AGENT),
            Err(RouteError::DuplicateConnection)
        ));
        router.unregister(AGENT, registration.generation());
        assert!(router.register(AGENT).is_ok());
    }

    #[test]
    fn stale_cleanup_cannot_remove_a_new_generation() {
        let router = BrokerRouter::new(1, 1);
        let old = router.register(AGENT).expect("old connection");
        let old_generation = old.generation();
        router.unregister(AGENT, old_generation);
        let new = router.register(AGENT).expect("new connection");
        let mut old = old;
        assert!(router.disconnect_and_requeue(&mut old, None).is_ok());
        assert_eq!(router.connection_count(), 1);
        router.unregister(AGENT, new.generation());
        assert_eq!(router.connection_count(), 0);
    }

    #[test]
    fn offline_fifo_is_bounded_and_observably_full() {
        let router = BrokerRouter::with_limits(1, 1, 2, 2);
        let first = frame(MessageType::PublicationResponse, AgentId::CA, AGENT, 1);
        let second = frame(MessageType::PublicationResponse, AgentId::CA, AGENT, 2);
        let third = frame(MessageType::PublicationResponse, AgentId::CA, AGENT, 3);
        assert!(router.route_ca_delivery(first.clone()).is_ok());
        assert!(router.route_ca_delivery(second.clone()).is_ok());
        assert_eq!(router.offline_len(AGENT), 2);
        assert_eq!(
            router.route_ca_delivery(third),
            Err(RouteError::OfflineQueueFull)
        );
        assert_eq!(router.offline_len(AGENT), 2);
        let mut registration = router.register(AGENT).expect("reconnect");
        assert_eq!(registration.pending.pop_front(), Some(first));
        assert_eq!(registration.pending.pop_front(), Some(second));
    }

    #[test]
    fn agent_requests_use_the_dedicated_ca_channel_and_reject_spoofing() {
        let router = BrokerRouter::with_limits(1, 1, 1, 1);
        let mut ca = router.take_ca_requests().expect("CA channel");
        let request = frame(MessageType::Publish, AGENT, AgentId::CA, 1);
        assert!(router.route_agent_request(AGENT, request.clone()).is_ok());
        assert_eq!(ca.try_recv(), Ok(request));
        let spoofed = frame(MessageType::Publish, AgentId([2; 16]), AgentId::CA, 2);
        assert_eq!(
            router.route_agent_request(AGENT, spoofed),
            Err(RouteError::Protocol(Error::BadSignature))
        );
    }

    #[test]
    fn zero_capacity_queues_fail_without_empty_offline_entries() {
        let offline = Arc::new(MemoryOfflineQueueStore::new(0));
        let router = BrokerRouter::with_offline_store(1, 1, 0, offline.clone());
        let delivery = frame(MessageType::PublicationResponse, AgentId::CA, AGENT, 1);
        assert_eq!(
            router.route_ca_delivery(delivery),
            Err(RouteError::OfflineQueueFull)
        );
        assert_eq!(offline.len(AGENT), 0);
        let request = frame(MessageType::Publish, AGENT, AgentId::CA, 2);
        assert_eq!(
            router.route_agent_request(AGENT, request),
            Err(RouteError::CaQueueFull)
        );
    }

    #[test]
    fn online_and_concurrent_offline_saturation_are_bounded() {
        let router = BrokerRouter::with_limits(1, 1, 1, 1);
        let _registration = router.register(AGENT).expect("online Agent");
        assert!(
            router
                .route_ca_delivery(frame(
                    MessageType::PublicationResponse,
                    AgentId::CA,
                    AGENT,
                    1,
                ))
                .is_ok()
        );
        assert_eq!(
            router.route_ca_delivery(frame(
                MessageType::PublicationResponse,
                AgentId::CA,
                AGENT,
                2,
            )),
            Err(RouteError::OnlineQueueFull)
        );

        let offline_agent = AgentId([3; 16]);
        let router = Arc::new(BrokerRouter::with_limits(1, 1, 1, 1));
        let mut workers = Vec::new();
        for marker in 3..=4 {
            let router = Arc::clone(&router);
            workers.push(std::thread::spawn(move || {
                router.route_ca_delivery(frame(
                    MessageType::PublicationResponse,
                    AgentId::CA,
                    offline_agent,
                    marker,
                ))
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(router.offline_len(offline_agent), 1);

        let ca_router = BrokerRouter::with_limits(1, 1, 1, 1);
        let _ca_receiver = ca_router.take_ca_requests().expect("CA receiver");
        assert!(
            ca_router
                .route_agent_request(AGENT, frame(MessageType::Publish, AGENT, AgentId::CA, 5))
                .is_ok()
        );
        assert_eq!(
            ca_router
                .route_agent_request(AGENT, frame(MessageType::Publish, AGENT, AgentId::CA, 6)),
            Err(RouteError::CaQueueFull)
        );
    }

    #[tokio::test]
    async fn disconnect_requeues_unsent_but_not_successfully_dequeued_best_effort_delivery() {
        let router = BrokerRouter::with_limits(1, 2, 2, 1);
        let queued = frame(MessageType::PublicationResponse, AgentId::CA, AGENT, 7);
        let mut registration = router.register(AGENT).expect("registration");
        router.route_ca_delivery(queued.clone()).unwrap();
        router
            .disconnect_and_requeue(&mut registration, None)
            .unwrap();
        assert_eq!(router.offline_len(AGENT), 1);

        let mut registration = router.register(AGENT).expect("reconnection");
        assert_eq!(registration.recv_best_effort().await, Some(queued));
        router
            .disconnect_and_requeue(&mut registration, None)
            .unwrap();
        assert_eq!(router.offline_len(AGENT), 0);
    }
}
