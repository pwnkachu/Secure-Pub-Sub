#![forbid(unsafe_code)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use agent_core::{Agent, AgentKeys, CaPublicKeys, FixedReplayCache};
use ed25519_dalek::SigningKey;
use protocol_core::{
    AgentId, AttributeId, AttributeRef, ClauseRef, Error, HandlerId, Operator, TypeId, ValueRef,
};
use tempfile::TempDir;
use transport::{FramedTransport, SystemRandom, TransportError};
use x25519_dalek::StaticSecret;

struct LoggedChild {
    name: String,
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Arc<Mutex<String>>,
}

impl LoggedChild {
    fn spawn(name: &str, command: &mut Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("capture {name} stdout"));
        let stderr = child
            .stderr
            .take()
            .unwrap_or_else(|| panic!("capture {name} stderr"));
        let (sender, lines) = mpsc::channel();
        let log = Arc::new(Mutex::new(String::new()));
        for (stream, label) in [
            (Box::new(stdout) as Box<dyn std::io::Read + Send>, "stdout"),
            (Box::new(stderr) as Box<dyn std::io::Read + Send>, "stderr"),
        ] {
            let sender = sender.clone();
            let log = Arc::clone(&log);
            let name = name.to_owned();
            thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if let Ok(mut output) = log.lock() {
                        output.push_str(&format!("[{name} {label}] {line}\n"));
                    }
                    let _ = sender.send(line);
                }
            });
        }
        Self {
            name: name.to_owned(),
            child,
            lines,
            log,
        }
    }

    fn wait_for(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            match self.lines.recv_timeout(remaining) {
                Ok(line) if line.contains(needle) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }

    fn wait_for_prefix(&self, prefix: &str, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        let mut preceding = Vec::new();
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(format!(
                    "timeout waiting for {prefix:?}; preceding lines: {preceding:?}\n{}",
                    self.diagnostics()
                ));
            };
            match self.lines.recv_timeout(remaining) {
                Ok(line) if line.starts_with(prefix) => return Ok(line),
                Ok(line) => preceding.push(line),
                Err(error) => {
                    return Err(format!(
                        "failed waiting for {prefix:?}: {error}; preceding lines: {preceding:?}\n{}",
                        self.diagnostics()
                    ));
                }
            }
        }
    }

    fn diagnostics(&self) -> String {
        self.log
            .lock()
            .map(|value| value.clone())
            .unwrap_or_else(|_| format!("{} log unavailable", self.name))
    }
}

impl Drop for LoggedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn binary(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/debug")
        .join(name)
}

fn key_pair(directory: &Path, name: &str, marker: u8) {
    let ed = [marker; 32];
    let x = [marker.wrapping_add(64); 32];
    fs::write(
        directory.join(format!("{name}-ed25519.secret")),
        hex::encode(ed),
    )
    .unwrap();
    fs::write(
        directory.join(format!("{name}-x25519.secret")),
        hex::encode(x),
    )
    .unwrap();
    fs::write(
        directory.join(format!("{name}-ed25519.public")),
        hex::encode(SigningKey::from_bytes(&ed).verifying_key().to_bytes()),
    )
    .unwrap();
    fs::write(
        directory.join(format!("{name}-x25519.public")),
        hex::encode(x25519_dalek::PublicKey::from(&StaticSecret::from(x)).to_bytes()),
    )
    .unwrap();
}

fn materialize(source: &Path, destination: &Path, secrets: &Path, address: &str) {
    let text = fs::read_to_string(source)
        .unwrap()
        .replace("127.0.0.1:7400", address)
        .replace("secrets/", &format!("{}/", secrets.display()));
    fs::write(destination, text).unwrap();
}

fn atomic_json(path: &Path, value: &serde_json::Value) {
    let temporary = path.with_extension("replacement");
    fs::write(&temporary, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    fs::rename(temporary, path).unwrap();
}

fn unused_address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("allocate test address")
        .to_string()
}

fn handshake_limit_probes(address: &str) {
    let mut first = TcpStream::connect(address).expect("first slow handshake");
    first
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut second = TcpStream::connect(address).expect("second slow handshake");
    second
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut third = TcpStream::connect(address).expect("third slow handshake");
    third
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(third.read(&mut byte).expect("bounded handshake close"), 0);
    assert_eq!(first.read(&mut byte).expect("handshake timeout close"), 0);
    assert_eq!(second.read(&mut byte).expect("handshake timeout close"), 0);
}

fn run_flow(
    cad: &LoggedChild,
    program: &str,
    subscriber: &Path,
    publisher: &Path,
    input: &str,
    expect_delivery: bool,
) {
    let mut subscriber_command = Command::new(binary(program));
    subscriber_command
        .args(["--config", subscriber.to_str().unwrap()])
        .stdin(Stdio::null());
    let subscriber_child =
        LoggedChild::spawn(&format!("{program}-subscriber"), &mut subscriber_command);
    assert!(
        subscriber_child.wait_for("request-submitted", Duration::from_secs(5)),
        "subscriber readiness timeout\n{}\n{}",
        subscriber_child.diagnostics(),
        cad.diagnostics()
    );

    let mut publisher_command = Command::new(binary(program));
    publisher_command
        .args(["--config", publisher.to_str().unwrap()])
        .stdin(Stdio::piped());
    let mut publisher_child =
        LoggedChild::spawn(&format!("{program}-publisher"), &mut publisher_command);
    publisher_child
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    assert!(
        publisher_child.wait_for("publication-submitted", Duration::from_secs(5)),
        "publisher timeout\n{}\n{}",
        publisher_child.diagnostics(),
        cad.diagnostics()
    );

    let delivered = subscriber_child.wait_for(
        if program == "robot-swarm-agent" {
            "telemetry-received"
        } else {
            "delivery-accepted"
        },
        Duration::from_millis(if expect_delivery { 5_000 } else { 800 }),
    );
    assert_eq!(
        delivered,
        expect_delivery,
        "unexpected delivery outcome\nsubscriber:\n{}\npublisher:\n{}\ncad:\n{}",
        subscriber_child.diagnostics(),
        publisher_child.diagnostics(),
        cad.diagnostics()
    );
    if !expect_delivery {
        assert!(
            cad.wait_for("request-rejected", Duration::from_secs(3)),
            "CA did not report rejection\n{}",
            cad.diagnostics()
        );
    }
}

fn tcp_security_probes(cad: &LoggedChild, broker: &LoggedChild, address: &str) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let ca_public = CaPublicKeys {
            ed25519: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            x25519: x25519_dalek::PublicKey::from(&StaticSecret::from([65; 32])).to_bytes(),
        };
        let publisher = Agent::new(
            AgentId([0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            AgentKeys::from_seeds([2; 32], [66; 32]),
            ca_public,
        );
        let subscriber = Agent::new(
            AgentId([0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            AgentKeys::from_seeds([3; 32], [67; 32]),
            ca_public,
        );
        let mut publisher_transport = FramedTransport::connect(address, Duration::from_secs(2))
            .await
            .unwrap();
        publisher_transport
            .send_hello(publisher.id())
            .await
            .unwrap();
        let mut subscriber_transport = FramedTransport::connect(address, Duration::from_secs(2))
            .await
            .unwrap();
        subscriber_transport
            .send_hello(subscriber.id())
            .await
            .unwrap();
        let mut rng = SystemRandom::new().unwrap();
        let publisher_environment = [
            AttributeRef {
                id: AttributeId(4097),
                value: ValueRef::Bytes(b"north"),
            },
            AttributeRef {
                id: AttributeId(4098),
                value: ValueRef::I64(2),
            },
            AttributeRef {
                id: AttributeId(4099),
                value: ValueRef::I64(1),
            },
            AttributeRef {
                id: AttributeId(4100),
                value: ValueRef::Bool(true),
            },
            AttributeRef {
                id: AttributeId(4102),
                value: ValueRef::Bool(true),
            },
            AttributeRef {
                id: AttributeId(4103),
                value: ValueRef::I64(2150),
            },
            AttributeRef {
                id: AttributeId(4105),
                value: ValueRef::Bytes(b"zone-a"),
            },
        ];
        let subscriber_environment = [
            AttributeRef {
                id: AttributeId(4097),
                value: ValueRef::Bytes(b"north"),
            },
            AttributeRef {
                id: AttributeId(4099),
                value: ValueRef::I64(2),
            },
            AttributeRef {
                id: AttributeId(4101),
                value: ValueRef::I64(1),
            },
            AttributeRef {
                id: AttributeId(4102),
                value: ValueRef::Bool(true),
            },
            AttributeRef {
                id: AttributeId(4105),
                value: ValueRef::Bytes(b"zone-a"),
            },
        ];
        subscriber_transport
            .send(
                &subscriber
                    .set_environment(&subscriber_environment, &mut rng)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            cad.wait_for("request-accepted", Duration::from_secs(5)),
            "{}",
            cad.diagnostics()
        );
        let handler = HandlerId([0x44; 16]);
        let predicate = [ClauseRef {
            attribute: AttributeId(4100),
            operator: Operator::Eq,
            value: ValueRef::Bool(true),
        }];
        subscriber_transport
            .send(
                &subscriber
                    .subscribe(TypeId(4097), handler, &predicate, &mut rng)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            cad.wait_for("request-accepted", Duration::from_secs(5)),
            "{}",
            cad.diagnostics()
        );
        publisher_transport
            .send(
                &publisher
                    .set_environment(&publisher_environment, &mut rng)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            cad.wait_for("request-accepted", Duration::from_secs(5)),
            "{}",
            cad.diagnostics()
        );
        let audience = [ClauseRef {
            attribute: AttributeId(4101),
            operator: Operator::Eq,
            value: ValueRef::I64(1),
        }];
        let mut tampered = publisher
            .publish(TypeId(4097), &audience, b"tampered", &mut rng)
            .unwrap();
        tampered[protocol_core::HEADER_LEN] ^= 1;
        publisher_transport.send(&tampered).await.unwrap();
        assert!(
            cad.wait_for("request-rejected", Duration::from_secs(5)),
            "{}",
            cad.diagnostics()
        );
        let replayed_request = publisher
            .publish(TypeId(4097), &audience, b"opaque", &mut rng)
            .unwrap();
        publisher_transport.send(&replayed_request).await.unwrap();
        publisher_transport.send(&replayed_request).await.unwrap();
        let delivery = subscriber_transport.receive().await.unwrap();
        assert!(
            cad.wait_for("request-rejected", Duration::from_secs(5)),
            "{}",
            cad.diagnostics()
        );
        assert!(matches!(
            subscriber_transport.receive().await,
            Err(TransportError::Timeout)
        ));
        let mut replay = FixedReplayCache::<16>::new(600);
        let mut wrong = delivery.clone();
        assert_eq!(
            subscriber
                .receive(&mut wrong, HandlerId([0x45; 16]), &mut replay, 1)
                .map(|_| ()),
            Err(Error::WrongHandler)
        );
        let mut accepted = delivery.clone();
        assert!(
            subscriber
                .receive(&mut accepted, handler, &mut replay, 1)
                .is_ok()
        );
        let mut duplicate = delivery;
        assert_eq!(
            subscriber
                .receive(&mut duplicate, handler, &mut replay, 1)
                .map(|_| ()),
            Err(Error::Replay)
        );

        subscriber_transport
            .send(
                &subscriber
                    .subscribe_permanent_request(TypeId(4097), handler, &predicate, &mut rng)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(cad.wait_for("request-accepted", Duration::from_secs(5)));
        drop(subscriber_transport);
        assert!(
            broker.wait_for(
                "agent-disconnected identity=AgentId(10000000000000000000000000000002)",
                Duration::from_secs(5)
            ),
            "subscriber disconnect was not observed\n{}",
            broker.diagnostics()
        );

        for value in [b"offline-first".as_slice(), b"offline-second".as_slice()] {
            publisher_transport
                .send(
                    &publisher
                        .publish(TypeId(4097), &audience, value, &mut rng)
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(cad.wait_for("publication-accepted", Duration::from_secs(5)));
        }

        let mut reconnected = FramedTransport::connect(address, Duration::from_secs(2))
            .await
            .unwrap();
        reconnected.send_hello(subscriber.id()).await.unwrap();
        for expected in [b"offline-first".as_slice(), b"offline-second".as_slice()] {
            let mut frame = reconnected.receive().await.unwrap();
            let received = subscriber
                .receive(&mut frame, handler, &mut replay, 2)
                .unwrap();
            assert_eq!(received.value, expected);
        }
    });
}

#[test]
fn separate_processes_authorize_and_reject_all_domains_over_tcp() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new("cargo")
        .args(["build", "--workspace", "--quiet"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success(), "workspace binaries could not be built");
    let temp = TempDir::new().unwrap();
    let secrets = temp.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    for (index, name) in [
        "ca",
        "building-sensor",
        "building-panel",
        "building-maintenance",
        "scout",
        "coordinator",
        "responder",
        "tenant-publisher",
        "tenant-consumer",
    ]
    .iter()
    .enumerate()
    {
        key_pair(&secrets, name, (index + 1) as u8);
    }
    fs::write(secrets.join("broker-ca.psk"), hex::encode([0xa5; 32])).unwrap();
    fs::write(secrets.join("wrong-broker-ca.psk"), hex::encode([0x5a; 32])).unwrap();

    let examples = root.join("config/examples");
    let ca_address = unused_address();
    let ca_config = temp.path().join("ca.json");
    materialize(
        &examples.join("ca.json"),
        &ca_config,
        &secrets,
        "127.0.0.1:7400",
    );
    let ca_text = fs::read_to_string(&ca_config)
        .unwrap()
        .replace("127.0.0.1:7500", &ca_address)
        .replace(
            "\"broker_auth_timeout_seconds\": 5",
            "\"broker_auth_timeout_seconds\": 1",
        )
        .replace(
            "state/ca.snapshot",
            &temp.path().join("ca.snapshot").display().to_string(),
        );
    fs::write(&ca_config, ca_text).unwrap();
    let mut cad_command = Command::new(binary("cad"));
    cad_command.args(["--config", ca_config.to_str().unwrap()]);
    let mut cad = LoggedChild::spawn("cad", &mut cad_command);
    assert!(
        cad.wait_for("cad ready", Duration::from_secs(5)),
        "cad readiness timeout\n{}\n{}",
        cad.diagnostics(),
        cad.diagnostics()
    );

    let unauthenticated = TcpStream::connect(&ca_address).expect("unauthenticated CA peer");
    assert!(
        cad.wait_for("broker-authentication-rejected", Duration::from_secs(3)),
        "unauthenticated peer did not expire\n{}",
        cad.diagnostics()
    );
    drop(unauthenticated);

    let mut wrong_broker_command = Command::new(binary("brokerd"));
    wrong_broker_command.args([
        "--listen",
        "127.0.0.1:0",
        "--ca",
        &ca_address,
        "--ca-psk-file",
        secrets.join("wrong-broker-ca.psk").to_str().unwrap(),
    ]);
    let wrong_broker = LoggedChild::spawn("wrong-brokerd", &mut wrong_broker_command);
    assert!(
        cad.wait_for("broker-authentication-rejected", Duration::from_secs(5)),
        "wrong PSK was not rejected\n{}\n{}",
        cad.diagnostics(),
        wrong_broker.diagnostics()
    );
    drop(wrong_broker);

    let mut broker_command = Command::new(binary("brokerd"));
    broker_command.args([
        "--listen",
        "127.0.0.1:0",
        "--ca",
        &ca_address,
        "--ca-psk-file",
        secrets.join("broker-ca.psk").to_str().unwrap(),
        "--agent-io-timeout-seconds",
        "20",
        "--agent-handshake-timeout-seconds",
        "1",
        "--max-pending-handshakes",
        "2",
    ]);
    let mut broker = LoggedChild::spawn("brokerd", &mut broker_command);
    let broker_line = broker
        .wait_for_prefix("brokerd listening on ", Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("broker readiness timeout: {error}"));
    let address = broker_line
        .strip_prefix("brokerd listening on ")
        .unwrap_or_else(|| panic!("unexpected broker readiness: {broker_line}"))
        .to_owned();
    assert!(
        cad.wait_for("broker-connected", Duration::from_secs(5)),
        "broker did not connect to CA\n{}\n{}",
        cad.diagnostics(),
        broker.diagnostics()
    );
    let mut second_broker_command = Command::new(binary("brokerd"));
    second_broker_command.args([
        "--listen",
        "127.0.0.1:0",
        "--ca",
        &ca_address,
        "--ca-psk-file",
        secrets.join("broker-ca.psk").to_str().unwrap(),
    ]);
    let second_broker = LoggedChild::spawn("second-brokerd", &mut second_broker_command);
    assert!(
        !second_broker.wait_for("ca-connected", Duration::from_millis(800)),
        "cad accepted a concurrent second broker\n{}",
        second_broker.diagnostics()
    );
    drop(second_broker);
    thread::sleep(Duration::from_secs(31));
    assert!(
        cad.child.try_wait().unwrap().is_none(),
        "idle CA listener exited\n{}",
        cad.diagnostics()
    );
    assert!(
        broker.child.try_wait().unwrap().is_none(),
        "idle Broker--CA link was closed\n{}",
        broker.diagnostics()
    );
    assert!(
        !cad.diagnostics().contains("broker-disconnected"),
        "idle Broker--CA connection was recycled\n{}",
        cad.diagnostics()
    );
    assert_eq!(
        cad.diagnostics().matches("broker-connected").count(),
        1,
        "cad must service exactly one broker link at a time"
    );

    handshake_limit_probes(&address);
    tcp_security_probes(&cad, &broker, &address);

    let cases = [
        (
            "smart-building-agent",
            "smart-building-control-panel.json",
            "smart-building-sensor.json",
            "2150\n",
            "north",
            "south",
        ),
        (
            "robot-swarm-agent",
            "swarm-coordinator.json",
            "swarm-scout.json",
            "battery=90\n",
            "alpha",
            "beta",
        ),
        (
            "multi-tenant-agent",
            "tenant-consumer.json",
            "tenant-publisher.json",
            "order.created\n",
            "tenant-a",
            "tenant-b",
        ),
    ];
    for (index, (program, subscriber_name, publisher_name, input, allowed, denied)) in
        cases.iter().enumerate()
    {
        let subscriber = temp.path().join(format!("subscriber-{index}.json"));
        let publisher = temp.path().join(format!("publisher-{index}.json"));
        materialize(
            &examples.join(subscriber_name),
            &subscriber,
            &secrets,
            &address,
        );
        materialize(
            &examples.join(publisher_name),
            &publisher,
            &secrets,
            &address,
        );
        run_flow(&cad, program, &subscriber, &publisher, input, true);
        let rejected = temp.path().join(format!("rejected-{index}.json"));
        fs::write(
            &rejected,
            fs::read_to_string(&publisher)
                .unwrap()
                .replace(allowed, denied),
        )
        .unwrap();
        run_flow(&cad, program, &subscriber, &rejected, input, false);
    }

    let subscriber_config = temp.path().join("reload-subscriber.json");
    let publisher_config = temp.path().join("reload-publisher.json");
    materialize(
        &examples.join("tenant-consumer.json"),
        &subscriber_config,
        &secrets,
        &address,
    );
    materialize(
        &examples.join("tenant-publisher.json"),
        &publisher_config,
        &secrets,
        &address,
    );
    let mut subscriber_command = Command::new(binary("multi-tenant-agent"));
    subscriber_command
        .args(["--config", subscriber_config.to_str().unwrap()])
        .stdin(Stdio::null());
    let subscriber = LoggedChild::spawn("reload-subscriber", &mut subscriber_command);
    assert!(
        subscriber.wait_for("request-submitted", Duration::from_secs(5)),
        "{}",
        subscriber.diagnostics()
    );
    let mut publisher_command = Command::new(binary("multi-tenant-agent"));
    publisher_command
        .args(["--config", publisher_config.to_str().unwrap()])
        .stdin(Stdio::piped());
    let mut publisher = LoggedChild::spawn("reload-publisher", &mut publisher_command);
    let mut publisher_stdin = publisher.child.stdin.take().unwrap();
    assert!(
        publisher.wait_for("request-submitted", Duration::from_secs(5)),
        "{}",
        publisher.diagnostics()
    );
    publisher_stdin.write_all(b"before-reload\n").unwrap();
    assert!(publisher.wait_for("publication-submitted", Duration::from_secs(5)));
    assert!(subscriber.wait_for("delivery-accepted", Duration::from_secs(5)));

    let original_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_config).unwrap()).unwrap();
    let mut invalid = original_config.clone();
    invalid["policy"]["isolations"][0]["attributes"] = serde_json::json!([]);
    atomic_json(&ca_config, &invalid);
    assert!(
        cad.wait_for("policy-reload-rejected", Duration::from_secs(5)),
        "{}",
        cad.diagnostics()
    );
    publisher_stdin
        .write_all(b"after-invalid-reload\n")
        .unwrap();
    assert!(publisher.wait_for("publication-submitted", Duration::from_secs(5)));
    assert!(
        subscriber.wait_for("delivery-accepted", Duration::from_secs(5)),
        "invalid policy replaced current policy\n{}",
        cad.diagnostics()
    );

    let mut revoked_policy = original_config.clone();
    revoked_policy["policy"]["approvals"]
        .as_array_mut()
        .unwrap()
        .retain(|approval| approval["agent"] != "30000000000000000000000000000002");
    atomic_json(&ca_config, &revoked_policy);
    assert!(
        cad.wait_for("configuration-reloaded", Duration::from_secs(5)),
        "{}",
        cad.diagnostics()
    );
    publisher_stdin
        .write_all(b"after-policy-revocation\n")
        .unwrap();
    assert!(publisher.wait_for("publication-submitted", Duration::from_secs(5)));
    assert!(
        !subscriber.wait_for("delivery-accepted", Duration::from_millis(800)),
        "revoked permanent subscription delivered\n{}",
        subscriber.diagnostics()
    );

    let mut revoked_agent = original_config;
    revoked_agent["agents"]
        .as_array_mut()
        .unwrap()
        .retain(|agent| agent["id"] != "30000000000000000000000000000001");
    atomic_json(&ca_config, &revoked_agent);
    assert!(
        cad.wait_for("configuration-reloaded", Duration::from_secs(5)),
        "{}",
        cad.diagnostics()
    );
    publisher_stdin
        .write_all(b"after-agent-revocation\n")
        .unwrap();
    assert!(publisher.wait_for("publication-submitted", Duration::from_secs(5)));
    assert!(
        cad.wait_for("request-rejected", Duration::from_secs(5)),
        "revoked Agent frame was not rejected\n{}",
        cad.diagnostics()
    );

    drop(cad);
    let mut restarted_command = Command::new(binary("cad"));
    restarted_command.args(["--config", ca_config.to_str().unwrap()]);
    cad = LoggedChild::spawn("cad-restarted", &mut restarted_command);
    assert!(
        cad.wait_for("cad ready", Duration::from_secs(5)),
        "snapshot restart failed\n{}",
        cad.diagnostics()
    );
    assert!(
        cad.wait_for("broker-connected", Duration::from_secs(5)),
        "broker did not reconnect to restarted CA\n{}\n{}",
        cad.diagnostics(),
        broker.diagnostics()
    );
    publisher_stdin.write_all(b"after-ca-restart\n").unwrap();
    assert!(publisher.wait_for("publication-submitted", Duration::from_secs(5)));
    assert!(
        cad.wait_for("request-rejected", Duration::from_secs(5)),
        "revocation did not survive restart\n{}",
        cad.diagnostics()
    );
}

#[test]
fn readiness_wait_ignores_concurrent_log_order() {
    let (sender, lines) = mpsc::channel();
    sender
        .send("brokerd event=ca-connected address=127.0.0.1:7500".to_owned())
        .unwrap();
    sender
        .send("brokerd listening on 127.0.0.1:7400".to_owned())
        .unwrap();
    drop(sender);
    let child = LoggedChild {
        name: "synthetic".to_owned(),
        child: Command::new("true").spawn().unwrap(),
        lines,
        log: Arc::new(Mutex::new(String::new())),
    };
    assert_eq!(
        child
            .wait_for_prefix("brokerd listening on ", Duration::from_secs(1))
            .unwrap(),
        "brokerd listening on 127.0.0.1:7400"
    );
}
