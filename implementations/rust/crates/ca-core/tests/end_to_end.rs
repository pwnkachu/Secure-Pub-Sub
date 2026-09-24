#![forbid(unsafe_code)]

use agent_core::{Agent, AgentKeys, CaPublicKeys};
use broker_core::BrokerRouter;
use ca_core::{
    AttributeType, AttributeValue, CaKeys, CertificateAuthority, DynamicEnvironmentPolicy,
    EnvironmentStore, KeyDirectory, MemoryStore, PersistentStore, ProcessResult, PublicKeys,
    ReplayCache, ReplayStore, StaticEnvironmentPolicy, StoreLimits, StoredSubscription,
    SubscriptionStore,
};
use protocol_core::{
    AgentId, AsyncTransport, AttributeId, AttributeRef, ClauseRef, Clock, Error, HandlerId,
    MAX_FRAME_LEN, MessageType, Operator, TypeId, ValueRef, parse_envelope,
};
use rand_core::SeedableRng;

const PUBLISHER_ID: AgentId = AgentId([1; 16]);
const SUBSCRIBER_ID: AgentId = AgentId([2; 16]);
const HANDLER: HandlerId = HandlerId([3; 16]);
const TYPE_ID: TypeId = TypeId(7);

fn fixture() -> (CertificateAuthority<MemoryStore>, Agent, Agent) {
    let ca_keys = CaKeys::from_seeds([31; 32], [32; 32]);
    let ca_public = CaPublicKeys {
        ed25519: ca_keys.verifying_key(),
        x25519: ca_keys.x25519_public(),
    };
    let publisher = Agent::new(
        PUBLISHER_ID,
        AgentKeys::from_seeds([11; 32], [12; 32]),
        ca_public,
    );
    let subscriber = Agent::new(
        SUBSCRIBER_ID,
        AgentKeys::from_seeds([21; 32], [22; 32]),
        ca_public,
    );
    let store = MemoryStore::default();
    assert!(
        store
            .provision(
                PUBLISHER_ID,
                PublicKeys {
                    ed25519: publisher.verifying_key(),
                    x25519: publisher.x25519_public(),
                }
            )
            .is_ok()
    );
    assert!(
        store
            .provision(
                SUBSCRIBER_ID,
                PublicKeys {
                    ed25519: subscriber.verifying_key(),
                    x25519: subscriber.x25519_public(),
                }
            )
            .is_ok()
    );
    (
        CertificateAuthority::new(ca_keys, store),
        publisher,
        subscriber,
    )
}

fn configure<P: ca_core::EnvironmentPolicy>(
    ca: &CertificateAuthority<MemoryStore, P>,
    publisher: &Agent,
    subscriber: &Agent,
    rng: &mut rand_chacha::ChaCha20Rng,
) {
    let publisher_environment = [AttributeRef {
        id: AttributeId(1),
        value: ValueRef::Bytes(b"temperature"),
    }];
    let subscriber_environment = [AttributeRef {
        id: AttributeId(2),
        value: ValueRef::Bool(true),
    }];
    let subscription = [ClauseRef {
        attribute: AttributeId(1),
        operator: Operator::Eq,
        value: ValueRef::Bytes(b"temperature"),
    }];
    let mut frame = publisher
        .set_environment(&publisher_environment, rng)
        .unwrap_or_default();
    assert!(matches!(
        ca.process(&mut frame, 1, rng),
        Ok(ProcessResult::Accepted)
    ));
    let mut frame = subscriber
        .set_environment(&subscriber_environment, rng)
        .unwrap_or_default();
    assert!(matches!(
        ca.process(&mut frame, 2, rng),
        Ok(ProcessResult::Accepted)
    ));
    let mut frame = subscriber
        .subscribe_permanent_request(TYPE_ID, HANDLER, &subscription, rng)
        .unwrap_or_default();
    assert!(matches!(
        ca.process(&mut frame, 3, rng),
        Ok(ProcessResult::Accepted)
    ));
}

fn policy_with_approvals(include_subscriber: bool) -> StaticEnvironmentPolicy {
    let mut policy = StaticEnvironmentPolicy::new();
    assert!(
        policy
            .register_ca_issued(AttributeId(1), AttributeType::Bytes)
            .is_ok()
    );
    assert!(
        policy
            .register_ca_issued(AttributeId(2), AttributeType::Bool)
            .is_ok()
    );
    assert!(
        policy
            .approve(
                PUBLISHER_ID,
                AttributeId(1),
                AttributeValue::bytes(b"temperature").unwrap_or_else(|_| unreachable!()),
            )
            .is_ok()
    );
    if include_subscriber {
        assert!(
            policy
                .approve(SUBSCRIBER_ID, AttributeId(2), AttributeValue::Bool(true),)
                .is_ok()
        );
    }
    policy
}

#[test]
fn policy_reload_revalidates_stored_environments_and_permanent_subscriptions() {
    let ca_keys = CaKeys::from_seeds([31; 32], [32; 32]);
    let ca_public = CaPublicKeys {
        ed25519: ca_keys.verifying_key(),
        x25519: ca_keys.x25519_public(),
    };
    let publisher = Agent::new(
        PUBLISHER_ID,
        AgentKeys::from_seeds([11; 32], [12; 32]),
        ca_public,
    );
    let subscriber = Agent::new(
        SUBSCRIBER_ID,
        AgentKeys::from_seeds([21; 32], [22; 32]),
        ca_public,
    );
    let store = MemoryStore::default();
    for agent in [&publisher, &subscriber] {
        assert!(
            store
                .provision(
                    agent.id(),
                    PublicKeys {
                        ed25519: agent.verifying_key(),
                        x25519: agent.x25519_public(),
                    }
                )
                .is_ok()
        );
    }
    let policy = DynamicEnvironmentPolicy::new(policy_with_approvals(true));
    let ca = CertificateAuthority::with_policy(ca_keys, store, policy.clone());
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([91; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let audience = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    let mut before = publisher
        .publish(TYPE_ID, &audience, b"before", &mut rng)
        .unwrap_or_default();
    assert!(
        matches!(ca.process(&mut before, 10, &mut rng), Ok(ProcessResult::Deliveries(values)) if values.len() == 1)
    );

    policy.replace(policy_with_approvals(false));
    let mut after = publisher
        .publish(TYPE_ID, &audience, b"after", &mut rng)
        .unwrap_or_default();
    assert!(
        matches!(ca.process(&mut after, 11, &mut rng), Ok(ProcessResult::Deliveries(values)) if values.is_empty())
    );
    assert!(matches!(ca.store().subscriptions_for(TYPE_ID), Ok(values) if values.len() == 1));
}

#[test]
fn bidirectional_authorization_delivery_and_response_replay() {
    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([44; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let audience = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    let mut publication = publisher
        .publish(TYPE_ID, &audience, b"21.5 C", &mut rng)
        .unwrap_or_default();
    let ProcessResult::Deliveries(mut deliveries) = ca
        .process(&mut publication, 4, &mut rng)
        .unwrap_or(ProcessResult::Accepted)
    else {
        panic!("expected deliveries");
    };
    assert_eq!(deliveries.len(), 1);
    let original = deliveries.remove(0);
    let mut first = original.clone();
    let mut replay = ReplayCache::new(16, 60);
    let delivery = subscriber.receive(&mut first, HANDLER, &mut replay, 5);
    assert_eq!(delivery.map(|item| item.value), Ok(b"21.5 C".as_slice()));
    let mut second = original;
    assert_eq!(
        subscriber
            .receive(&mut second, HANDLER, &mut replay, 6)
            .map(|_| ()),
        Err(Error::Replay)
    );
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_seconds(&self) -> u64 {
        50
    }
}

struct ScriptedTransport {
    sent: Vec<Vec<u8>>,
    received: std::collections::VecDeque<Vec<u8>>,
}

impl AsyncTransport for ScriptedTransport {
    type Error = ();

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    async fn receive(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let frame = self.received.pop_front().ok_or(())?;
        let destination = output.get_mut(..frame.len()).ok_or(())?;
        destination.copy_from_slice(&frame);
        Ok(frame.len())
    }
}

#[tokio::test]
async fn permanent_subscription_reuses_handler_for_every_matching_publication() {
    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([48; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let audience = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    let mut received = std::collections::VecDeque::new();
    for value in [b"first".as_slice(), b"second".as_slice()] {
        let mut publication = publisher
            .publish(TYPE_ID, &audience, value, &mut rng)
            .unwrap_or_default();
        let ProcessResult::Deliveries(mut deliveries) = ca
            .process(&mut publication, 40, &mut rng)
            .unwrap_or(ProcessResult::Accepted)
        else {
            panic!("expected deliveries");
        };
        assert_eq!(deliveries.len(), 1);
        received.push_back(deliveries.remove(0));
    }

    let mut transport = ScriptedTransport {
        sent: Vec::new(),
        received,
    };
    let mut replay = ReplayCache::new(8, 60);
    let mut frame = [0u8; MAX_FRAME_LEN];
    let predicate = [ClauseRef {
        attribute: AttributeId(1),
        operator: Operator::Eq,
        value: ValueRef::Bytes(b"temperature"),
    }];
    let mut handled = 0;
    let result = subscriber
        .subscribe_permanent(
            TYPE_ID,
            HANDLER,
            &predicate,
            &mut transport,
            &mut replay,
            &FixedClock,
            &mut rng,
            &mut frame,
            |delivery: agent_core::Delivery<'_>| {
                assert_eq!(delivery.handler, HANDLER);
                assert_eq!(delivery.type_id, TYPE_ID);
                handled += 1;
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(agent_core::SubscriptionError::Transport(()))
    ));
    assert_eq!(handled, 2);
    assert_eq!(transport.sent.len(), 1);
    let request = parse_envelope(&transport.sent[0]).unwrap_or_else(|_| panic!("subscribe frame"));
    assert_eq!(request.message_type, MessageType::SubscribePermanent);
    assert_eq!(request.handler, HANDLER);
}

#[test]
fn one_shot_subscription_is_consumed_by_exactly_one_concurrent_match() {
    use std::sync::Arc;

    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([49; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let predicate = [ClauseRef {
        attribute: AttributeId(1),
        operator: Operator::Eq,
        value: ValueRef::Bytes(b"temperature"),
    }];
    let mut one_shot = subscriber
        .subscribe(TYPE_ID, HANDLER, &predicate, &mut rng)
        .unwrap_or_default();
    assert!(matches!(
        ca.process(&mut one_shot, 41, &mut rng),
        Ok(ProcessResult::Accepted)
    ));

    let audience = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    let frames: Vec<_> = (0..8)
        .map(|_| {
            publisher
                .publish(TYPE_ID, &audience, b"one shot", &mut rng)
                .unwrap_or_default()
        })
        .collect();
    let ca = Arc::new(ca);
    let handles: Vec<_> = frames
        .into_iter()
        .enumerate()
        .map(|(index, mut frame)| {
            let ca = Arc::clone(&ca);
            std::thread::spawn(move || {
                let mut rng = rand_chacha::ChaCha20Rng::from_seed([(index as u8) + 80; 32]);
                ca.process(&mut frame, 42, &mut rng)
            })
        })
        .collect();
    let deliveries: usize = handles
        .into_iter()
        .filter_map(|handle| handle.join().ok())
        .filter_map(Result::ok)
        .map(|result| match result {
            ProcessResult::Accepted => 0,
            ProcessResult::Deliveries(deliveries) => deliveries.len(),
        })
        .sum();

    assert_eq!(deliveries, 1);
    assert!(matches!(ca.store().subscriptions_for(TYPE_ID), Ok(values) if values.is_empty()));
}

#[test]
fn one_shot_subscription_survives_non_match_then_is_consumed() {
    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([50; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let predicate = [ClauseRef {
        attribute: AttributeId(1),
        operator: Operator::Eq,
        value: ValueRef::Bytes(b"temperature"),
    }];
    let mut one_shot = subscriber
        .subscribe(TYPE_ID, HANDLER, &predicate, &mut rng)
        .unwrap_or_default();
    assert!(ca.process(&mut one_shot, 43, &mut rng).is_ok());

    let denied = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(false),
    }];
    let mut denied_publication = publisher
        .publish(TYPE_ID, &denied, b"denied", &mut rng)
        .unwrap_or_default();
    assert!(matches!(
        ca.process(&mut denied_publication, 44, &mut rng),
        Ok(ProcessResult::Deliveries(values)) if values.is_empty()
    ));
    assert!(matches!(ca.store().subscriptions_for(TYPE_ID), Ok(values) if values.len() == 1));

    let allowed = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    for expected in [1, 0] {
        let mut publication = publisher
            .publish(TYPE_ID, &allowed, b"allowed", &mut rng)
            .unwrap_or_default();
        assert!(matches!(
            ca.process(&mut publication, 45, &mut rng),
            Ok(ProcessResult::Deliveries(values)) if values.len() == expected
        ));
    }
}

#[test]
fn reconnect_registration_with_stable_handler_is_one_logical_one_shot() {
    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([53; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let predicate = [ClauseRef {
        attribute: AttributeId(1),
        operator: Operator::Eq,
        value: ValueRef::Bytes(b"temperature"),
    }];
    for now in 100..103 {
        let mut request = subscriber
            .subscribe(TYPE_ID, HANDLER, &predicate, &mut rng)
            .unwrap_or_default();
        assert!(ca.process(&mut request, now, &mut rng).is_ok());
        assert_eq!(
            ca.store()
                .subscriptions_for(TYPE_ID)
                .unwrap_or_default()
                .len(),
            1
        );
    }
}

#[test]
fn tamper_wrong_handler_cross_type_and_failed_predicate_are_rejected() {
    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([45; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let audience = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    let mut tampered = publisher
        .publish(TYPE_ID, &audience, b"secret", &mut rng)
        .unwrap_or_default();
    if let Some(byte) = tampered.get_mut(protocol_core::HEADER_LEN) {
        *byte ^= 1;
    }
    assert_eq!(
        ca.process(&mut tampered, 4, &mut rng).map(|_| ()),
        Err(Error::BadSignature)
    );

    let mut cross_type = publisher
        .publish(TypeId(8), &audience, b"secret", &mut rng)
        .unwrap_or_default();
    assert!(
        matches!(ca.process(&mut cross_type, 5, &mut rng), Ok(ProcessResult::Deliveries(values)) if values.is_empty())
    );

    let denied = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(false),
    }];
    let mut denied_frame = publisher
        .publish(TYPE_ID, &denied, b"secret", &mut rng)
        .unwrap_or_default();
    assert!(
        matches!(ca.process(&mut denied_frame, 6, &mut rng), Ok(ProcessResult::Deliveries(values)) if values.is_empty())
    );

    let mut allowed = publisher
        .publish(TYPE_ID, &audience, b"secret", &mut rng)
        .unwrap_or_default();
    let ProcessResult::Deliveries(mut values) = ca
        .process(&mut allowed, 7, &mut rng)
        .unwrap_or(ProcessResult::Accepted)
    else {
        panic!("expected delivery");
    };
    let mut delivery = values.pop().unwrap_or_default();
    let mut replay = ReplayCache::new(16, 60);
    assert_eq!(
        subscriber
            .receive(&mut delivery, HandlerId([9; 16]), &mut replay, 8)
            .map(|_| ()),
        Err(Error::WrongHandler)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_broker_ca_broker_agent_end_to_end() {
    let (ca, publisher, subscriber) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([46; 32]);
    configure(&ca, &publisher, &subscriber, &mut rng);
    let broker = BrokerRouter::new(8, 8);
    let mut ca_queue = broker
        .take_ca_requests()
        .unwrap_or_else(|| panic!("CA request channel"));
    let mut subscriber_queue = broker
        .register(SUBSCRIBER_ID)
        .unwrap_or_else(|_| panic!("subscriber registration"));
    let audience = [ClauseRef {
        attribute: AttributeId(2),
        operator: Operator::Eq,
        value: ValueRef::Bool(true),
    }];
    let publication = publisher
        .publish(TYPE_ID, &audience, b"routed", &mut rng)
        .unwrap_or_default();
    assert!(broker.route(PUBLISHER_ID, publication).await.is_ok());
    let mut at_ca = ca_queue.recv().await.unwrap_or_default();
    let ProcessResult::Deliveries(deliveries) = ca
        .process(&mut at_ca, 10, &mut rng)
        .unwrap_or(ProcessResult::Accepted)
    else {
        panic!("expected deliveries");
    };
    for delivery in deliveries {
        assert!(broker.route(AgentId::CA, delivery).await.is_ok());
    }
    let mut at_subscriber = subscriber_queue
        .recv_best_effort()
        .await
        .unwrap_or_default();
    let mut replay = ReplayCache::new(8, 60);
    let received = subscriber.receive(&mut at_subscriber, HANDLER, &mut replay, 11);
    assert_eq!(received.map(|item| item.value), Ok(b"routed".as_slice()));
}

#[test]
fn concurrent_duplicate_request_is_accepted_once() {
    use std::sync::{Arc, Barrier};

    let (ca, publisher, _) = fixture();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([47; 32]);
    let environment = [AttributeRef {
        id: AttributeId(1),
        value: ValueRef::I64(1),
    }];
    let frame = publisher
        .set_environment(&environment, &mut rng)
        .unwrap_or_default();
    let ca = Arc::new(ca);
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for index in 0..8u8 {
        let ca = Arc::clone(&ca);
        let barrier = Arc::clone(&barrier);
        let mut copy = frame.clone();
        handles.push(std::thread::spawn(move || {
            let mut local_rng = rand_chacha::ChaCha20Rng::from_seed([index; 32]);
            barrier.wait();
            ca.process(&mut copy, 20, &mut local_rng)
        }));
    }
    let accepted = handles
        .into_iter()
        .filter_map(|handle| handle.join().ok())
        .filter(Result::is_ok)
        .count();
    assert_eq!(accepted, 1);
}

#[test]
fn multiple_publishers_and_subscribers_are_concurrent_and_bounded() {
    use std::sync::Arc;

    let ca_keys = CaKeys::from_seeds([61; 32], [62; 32]);
    let ca_public = CaPublicKeys {
        ed25519: ca_keys.verifying_key(),
        x25519: ca_keys.x25519_public(),
    };
    let store = MemoryStore::default();
    let mut publishers = Vec::new();
    let mut subscribers = Vec::new();
    for index in 1..=4u8 {
        let publisher = Agent::new(
            AgentId([index; 16]),
            AgentKeys::from_seeds([index; 32], [index.saturating_add(10); 32]),
            ca_public,
        );
        assert!(
            store
                .provision(
                    publisher.id(),
                    PublicKeys {
                        ed25519: publisher.verifying_key(),
                        x25519: publisher.x25519_public(),
                    }
                )
                .is_ok()
        );
        publishers.push(publisher);

        let subscriber_id = AgentId([index.saturating_add(100); 16]);
        let subscriber = Agent::new(
            subscriber_id,
            AgentKeys::from_seeds(
                [index.saturating_add(20); 32],
                [index.saturating_add(30); 32],
            ),
            ca_public,
        );
        assert!(
            store
                .provision(
                    subscriber_id,
                    PublicKeys {
                        ed25519: subscriber.verifying_key(),
                        x25519: subscriber.x25519_public(),
                    }
                )
                .is_ok()
        );
        subscribers.push(subscriber);
    }
    let ca = CertificateAuthority::new(ca_keys, store);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([63; 32]);
    for publisher in &publishers {
        let mut frame = publisher
            .set_environment(
                &[AttributeRef {
                    id: AttributeId(1),
                    value: ValueRef::Bool(true),
                }],
                &mut rng,
            )
            .unwrap_or_default();
        assert!(ca.process(&mut frame, 30, &mut rng).is_ok());
    }
    for (index, subscriber) in subscribers.iter().enumerate() {
        let mut environment = subscriber
            .set_environment(
                &[AttributeRef {
                    id: AttributeId(2),
                    value: ValueRef::Bool(true),
                }],
                &mut rng,
            )
            .unwrap_or_default();
        assert!(ca.process(&mut environment, 31, &mut rng).is_ok());
        let mut subscription = subscriber
            .subscribe_permanent_request(
                TYPE_ID,
                HandlerId([(index as u8).saturating_add(1); 16]),
                &[ClauseRef {
                    attribute: AttributeId(1),
                    operator: Operator::Eq,
                    value: ValueRef::Bool(true),
                }],
                &mut rng,
            )
            .unwrap_or_default();
        assert!(ca.process(&mut subscription, 32, &mut rng).is_ok());
    }
    let ca = Arc::new(ca);
    let handles: Vec<_> = publishers
        .into_iter()
        .enumerate()
        .map(|(index, publisher)| {
            let ca = Arc::clone(&ca);
            std::thread::spawn(move || {
                let mut rng =
                    rand_chacha::ChaCha20Rng::from_seed([(index as u8).saturating_add(70); 32]);
                let mut frame = publisher
                    .publish(
                        TYPE_ID,
                        &[ClauseRef {
                            attribute: AttributeId(2),
                            operator: Operator::Eq,
                            value: ValueRef::Bool(true),
                        }],
                        b"value",
                        &mut rng,
                    )
                    .unwrap_or_default();
                ca.process(&mut frame, 40, &mut rng)
            })
        })
        .collect();
    let delivery_count: usize = handles
        .into_iter()
        .filter_map(|handle| handle.join().ok())
        .filter_map(Result::ok)
        .map(|result| match result {
            ProcessResult::Deliveries(deliveries) => deliveries.len(),
            ProcessResult::Accepted => 0,
        })
        .sum();
    assert_eq!(delivery_count, 16);
}

#[test]
fn persistent_store_round_trips_environment_subscription_and_replay_state() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
    let path = directory.path().join("state.snapshot");
    let limits = StoreLimits::default();
    let store = PersistentStore::open(&path, limits).unwrap_or_else(|_| panic!("open store"));
    let agent = AgentId([77; 16]);
    assert!(
        store
            .provision(
                agent,
                PublicKeys {
                    ed25519: [1; 32],
                    x25519: [2; 32]
                }
            )
            .is_ok()
    );
    let mut encoded = [0u8; 64];
    let length = protocol_core::encode_environment(
        &mut encoded,
        &[AttributeRef {
            id: AttributeId(9),
            value: ValueRef::Bool(true),
        }],
    )
    .unwrap_or(0);
    assert!(
        store
            .set_environment(agent, encoded[..length].to_vec())
            .is_ok()
    );
    assert!(
        store
            .check_and_mark(agent, protocol_core::SessionId([8; 16]), 50)
            .is_ok()
    );
    let mut subscription = [0u8; 64];
    let subscription_len = protocol_core::encode_subscribe_permanent(
        &mut subscription,
        TYPE_ID,
        &[ClauseRef {
            attribute: AttributeId(9),
            operator: Operator::Eq,
            value: ValueRef::Bool(true),
        }],
    )
    .unwrap_or(0);
    assert!(
        store
            .put_subscription(StoredSubscription {
                subscriber: agent,
                type_id: TYPE_ID,
                handler: HANDLER,
                kind: ca_core::SubscriptionKind::Permanent,
                encoded: subscription[..subscription_len].to_vec(),
            })
            .is_ok()
    );
    drop(store);

    let reopened = PersistentStore::open(&path, limits).unwrap_or_else(|_| panic!("reopen store"));
    assert!(matches!(reopened.environment(agent), Ok(Some(value)) if value == encoded[..length]));
    assert_eq!(
        reopened.check_and_mark(agent, protocol_core::SessionId([8; 16]), 51),
        Err(Error::Replay)
    );
    assert!(
        matches!(reopened.subscriptions_for(TYPE_ID), Ok(values) if values.len() == 1
            && values[0].subscriber == agent
            && values[0].handler == HANDLER)
    );
}

#[test]
fn persistent_agent_reconciliation_revokes_state_rotates_keys_and_is_atomic() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
    let state_directory = directory.path().join("store");
    assert!(std::fs::create_dir(&state_directory).is_ok());
    let path = state_directory.join("state.snapshot");
    let limits = StoreLimits {
        agents: 2,
        ..StoreLimits::default()
    };
    let store = PersistentStore::open(&path, limits).unwrap_or_else(|_| panic!("open store"));
    let revoked = AgentId([71; 16]);
    let retained = AgentId([72; 16]);
    let revoked_keys = PublicKeys {
        ed25519: [1; 32],
        x25519: [2; 32],
    };
    let retained_keys = PublicKeys {
        ed25519: [3; 32],
        x25519: [4; 32],
    };
    assert!(
        store
            .reconcile_agents(&[(revoked, revoked_keys), (retained, retained_keys)])
            .is_ok()
    );

    let mut encoded = [0u8; 64];
    let length = protocol_core::encode_environment(
        &mut encoded,
        &[AttributeRef {
            id: AttributeId(9),
            value: ValueRef::Bool(true),
        }],
    )
    .unwrap_or(0);
    assert!(
        store
            .set_environment(revoked, encoded[..length].to_vec())
            .is_ok()
    );
    let mut subscription = [0u8; 64];
    let subscription_len = protocol_core::encode_subscribe_permanent(
        &mut subscription,
        TYPE_ID,
        &[ClauseRef {
            attribute: AttributeId(9),
            operator: Operator::Eq,
            value: ValueRef::Bool(true),
        }],
    )
    .unwrap_or(0);
    assert!(
        store
            .put_subscription(StoredSubscription {
                subscriber: revoked,
                type_id: TYPE_ID,
                handler: HANDLER,
                kind: ca_core::SubscriptionKind::Permanent,
                encoded: subscription[..subscription_len].to_vec(),
            })
            .is_ok()
    );
    let old_session = protocol_core::SessionId([19; 16]);
    assert!(store.check_and_mark(revoked, old_session, 1).is_ok());

    assert!(store.reconcile_agents(&[(retained, retained_keys)]).is_ok());
    assert_eq!(store.keys(revoked).map(|_| ()), Err(Error::BadSignature));
    assert!(matches!(store.environment(revoked), Ok(None)));
    assert!(matches!(store.subscriptions_for(TYPE_ID), Ok(values) if values.is_empty()));
    assert!(store.check_and_mark(revoked, old_session, 2).is_ok());

    let rotated = PublicKeys {
        ed25519: [5; 32],
        x25519: [6; 32],
    };
    assert!(
        store
            .set_environment(retained, encoded[..length].to_vec())
            .is_ok()
    );
    assert!(store.reconcile_agents(&[(retained, rotated)]).is_ok());
    assert_eq!(store.keys(retained).ok(), Some(rotated));
    assert!(matches!(store.environment(retained), Ok(None)));
    assert_eq!(
        store.reconcile_agents(&[(AgentId::CA, rotated)]),
        Err(Error::Malformed)
    );
    assert_eq!(
        store.reconcile_agents(&[
            (retained, rotated),
            (revoked, revoked_keys),
            (AgentId([73; 16]), retained_keys)
        ]),
        Err(Error::Capacity)
    );
    assert_eq!(store.keys(retained).ok(), Some(rotated));

    assert!(std::fs::remove_file(&path).is_ok());
    assert!(std::fs::remove_dir(&state_directory).is_ok());
    assert_eq!(
        store.reconcile_agents(&[(revoked, revoked_keys)]),
        Err(Error::Capacity)
    );
    assert_eq!(store.keys(retained).ok(), Some(rotated));
    assert_eq!(store.keys(revoked).map(|_| ()), Err(Error::BadSignature));
}

#[test]
fn revoked_agent_signed_frame_is_rejected_after_reconciliation() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("temporary directory"));
    let path = directory.path().join("state.snapshot");
    let ca_keys = CaKeys::from_seeds([81; 32], [82; 32]);
    let ca_public = CaPublicKeys {
        ed25519: ca_keys.verifying_key(),
        x25519: ca_keys.x25519_public(),
    };
    let agent = Agent::new(
        AgentId([83; 16]),
        AgentKeys::from_seeds([84; 32], [85; 32]),
        ca_public,
    );
    let store = PersistentStore::open(&path, StoreLimits::default())
        .unwrap_or_else(|_| panic!("open store"));
    assert!(
        store
            .reconcile_agents(&[(
                agent.id(),
                PublicKeys {
                    ed25519: agent.verifying_key(),
                    x25519: agent.x25519_public(),
                }
            )])
            .is_ok()
    );
    assert!(store.reconcile_agents(&[]).is_ok());
    let ca = CertificateAuthority::new(ca_keys, store);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([86; 32]);
    let mut frame = agent
        .set_environment(
            &[AttributeRef {
                id: AttributeId(1),
                value: ValueRef::Bool(true),
            }],
            &mut rng,
        )
        .unwrap_or_default();
    assert_eq!(
        ca.process(&mut frame, 1, &mut rng).map(|_| ()),
        Err(Error::BadSignature)
    );
}
