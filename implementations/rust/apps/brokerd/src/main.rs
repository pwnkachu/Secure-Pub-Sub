#![forbid(unsafe_code)]

use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use broker_core::{
    BrokerRouter, DEFAULT_CA_QUEUE_DEPTH, DEFAULT_MAX_CONNECTIONS, DEFAULT_OFFLINE_QUEUE_DEPTH,
    DEFAULT_QUEUE_DEPTH,
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use infrastructure_link::{
    DedupWindow, FrameKind, LinkError, MessageId, PendingFrames, authentication_mac, decode, encode,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    time::{sleep, timeout},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use transport::FramedTransport;

struct CaLinkConfig {
    address: SocketAddr,
    connect_deadline: Duration,
    reconnect_min: Duration,
    reconnect_max: Duration,
    retry_period: Duration,
    psk: [u8; 32],
    pending_depth: usize,
    dedup_depth: usize,
}

struct CaSessionConfig {
    io_deadline: Duration,
    retry_period: Duration,
}

#[derive(Parser)]
#[command(about = "SecurePubSub bounded opaque-envelope broker")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7400")]
    listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:7500")]
    ca: SocketAddr,
    #[arg(long)]
    ca_psk_file: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_pending_handshakes: usize,
    #[arg(long, default_value_t = DEFAULT_QUEUE_DEPTH)]
    online_queue_depth: usize,
    #[arg(long, default_value_t = DEFAULT_OFFLINE_QUEUE_DEPTH)]
    offline_queue_depth: usize,
    #[arg(long, default_value_t = DEFAULT_CA_QUEUE_DEPTH)]
    ca_queue_depth: usize,
    #[arg(long, default_value_t = 10)]
    agent_handshake_timeout_seconds: u64,
    #[arg(long, default_value_t = 300)]
    agent_io_timeout_seconds: u64,
    #[arg(long, default_value_t = 5)]
    ca_connect_timeout_seconds: u64,
    #[arg(long, default_value_t = 1)]
    ca_reconnect_min_seconds: u64,
    #[arg(long, default_value_t = 30)]
    ca_reconnect_max_seconds: u64,
    #[arg(long, default_value_t = 2)]
    ca_ack_retry_seconds: u64,
    #[arg(long, default_value_t = DEFAULT_CA_QUEUE_DEPTH * 2)]
    ca_dedup_depth: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await?;
    let ca_psk = read_psk(&args.ca_psk_file)?;
    let bound_address = listener.local_addr()?;
    let router = BrokerRouter::with_limits(
        args.max_connections,
        args.online_queue_depth,
        args.offline_queue_depth,
        args.ca_queue_depth,
    );
    let ca_requests = router
        .take_ca_requests()
        .ok_or("CA request receiver already taken")?;
    tokio::spawn(maintain_ca_link(
        CaLinkConfig {
            address: args.ca,
            connect_deadline: Duration::from_secs(args.ca_connect_timeout_seconds.max(1)),
            reconnect_min: Duration::from_secs(args.ca_reconnect_min_seconds.max(1)),
            reconnect_max: Duration::from_secs(
                args.ca_reconnect_max_seconds
                    .max(args.ca_reconnect_min_seconds)
                    .max(1),
            ),
            retry_period: Duration::from_secs(args.ca_ack_retry_seconds.max(1)),
            psk: ca_psk,
            pending_depth: args.ca_queue_depth,
            dedup_depth: args.ca_dedup_depth,
        },
        router.clone(),
        ca_requests,
    ));

    let handshakes = std::sync::Arc::new(Semaphore::new(args.max_pending_handshakes));
    println!("brokerd listening on {bound_address}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(handshake_permit) = handshakes.clone().try_acquire_owned() else {
            eprintln!("brokerd event=handshake-rejected reason=limit peer={peer}");
            continue;
        };
        let router = router.clone();
        let handshake_deadline = Duration::from_secs(args.agent_handshake_timeout_seconds.max(1));
        let io_deadline = Duration::from_secs(args.agent_io_timeout_seconds.max(1));
        tokio::spawn(async move {
            let mut transport = FramedTransport::new(stream, handshake_deadline);
            let identity = match transport.receive_hello().await {
                Ok(identity) => identity,
                Err(error) => {
                    eprintln!("brokerd event=handshake-rejected reason={error}");
                    return;
                }
            };
            let mut registration = match router.register(identity) {
                Ok(registration) => registration,
                Err(error) => {
                    eprintln!(
                        "brokerd event=registration-rejected identity={identity:?} reason={error}"
                    );
                    return;
                }
            };
            drop(handshake_permit);
            let generation = registration.generation();
            let (mut writer, mut reader) = transport.into_inner().split();
            let mut undelivered = None;
            loop {
                tokio::select! {
                    maybe_frame = registration.recv_best_effort() => {
                        let Some(frame) = maybe_frame else { break };
                        if !matches!(timeout(io_deadline, writer.send(frame.clone().into())).await, Ok(Ok(()))) {
                            undelivered = Some(frame);
                            break;
                        }
                    }
                    received = timeout(io_deadline, reader.next()) => {
                        let Ok(Some(Ok(bytes))) = received else { break };
                        if let Err(error) = router.route_agent_request(identity, bytes.to_vec()) {
                            eprintln!("brokerd event=agent-frame-rejected identity={identity:?} reason={error}");
                            break;
                        }
                    }
                }
            }
            if let Err(error) = router.disconnect_and_requeue(&mut registration, undelivered) {
                eprintln!(
                    "brokerd event=delivery-requeue-failed identity={identity:?} generation={generation} reason={error}"
                );
            }
            println!(
                "brokerd event=agent-disconnected identity={identity:?} generation={generation}"
            );
        });
    }
}

fn read_psk(path: &PathBuf) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let bytes = hex::decode(text.trim())?;
    bytes
        .try_into()
        .map_err(|_| "Broker--CA PSK must contain exactly 32 bytes".into())
}

fn random_id() -> Result<MessageId, LinkError> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| LinkError::Authentication)?;
    Ok(MessageId(id))
}

async fn maintain_ca_link(
    config: CaLinkConfig,
    router: BrokerRouter,
    mut requests: mpsc::Receiver<Vec<u8>>,
) {
    let mut backoff = config.reconnect_min;
    let mut pending = PendingFrames::new(config.pending_depth);
    let mut acquired_deliveries = DedupWindow::new(config.dedup_depth);
    loop {
        let connected = timeout(config.connect_deadline, TcpStream::connect(config.address)).await;
        match connected {
            Ok(Ok(stream)) => {
                if stream.set_nodelay(true).is_err() {
                    sleep(backoff).await;
                    continue;
                }
                let mut framed = Framed::new(stream, infrastructure_link::codec());
                if let Err(error) =
                    authenticate_ca(&mut framed, &config.psk, config.connect_deadline).await
                {
                    eprintln!(
                        "brokerd event=ca-authentication-failed address={} reason={error}",
                        config.address
                    );
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(config.reconnect_max);
                    continue;
                }
                println!("brokerd event=ca-connected address={}", config.address);
                backoff = config.reconnect_min;
                let (writer, reader) = framed.split();
                run_ca_session(
                    writer,
                    reader,
                    &CaSessionConfig {
                        io_deadline: config.connect_deadline,
                        retry_period: config.retry_period,
                    },
                    &router,
                    &mut requests,
                    &mut pending,
                    &mut acquired_deliveries,
                )
                .await;
                eprintln!("brokerd event=ca-disconnected address={}", config.address);
            }
            Ok(Err(error)) => {
                eprintln!(
                    "brokerd event=ca-connect-failed address={} reason={error}",
                    config.address
                )
            }
            Err(_) => eprintln!(
                "brokerd event=ca-connect-failed address={} reason=timeout",
                config.address
            ),
        }
        sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(config.reconnect_max);
    }
}

async fn authenticate_ca(
    framed: &mut Framed<TcpStream, LengthDelimitedCodec>,
    psk: &[u8; 32],
    deadline: Duration,
) -> Result<(), LinkError> {
    let incoming = timeout(deadline, framed.next())
        .await
        .map_err(|_| LinkError::Authentication)?
        .ok_or(LinkError::Authentication)?
        .map_err(|_| LinkError::Authentication)?;
    let challenge = decode(&incoming)?;
    if challenge.kind != FrameKind::AuthChallenge || challenge.payload.len() != 32 {
        return Err(LinkError::Authentication);
    }
    let challenge_bytes: &[u8; 32] = challenge
        .payload
        .try_into()
        .map_err(|_| LinkError::Authentication)?;
    let response = encode(
        FrameKind::AuthResponse,
        challenge.id,
        &authentication_mac(psk, challenge_bytes),
    )?;
    timeout(deadline, framed.send(response.into()))
        .await
        .map_err(|_| LinkError::Authentication)?
        .map_err(|_| LinkError::Authentication)?;
    let incoming = timeout(deadline, framed.next())
        .await
        .map_err(|_| LinkError::Authentication)?
        .ok_or(LinkError::Authentication)?
        .map_err(|_| LinkError::Authentication)?;
    let accepted = decode(&incoming)?;
    if accepted.kind == FrameKind::AuthOk && accepted.id == challenge.id {
        Ok(())
    } else {
        Err(LinkError::Authentication)
    }
}

async fn run_ca_session(
    mut writer: SplitSink<Framed<TcpStream, LengthDelimitedCodec>, bytes::Bytes>,
    mut reader: futures_util::stream::SplitStream<Framed<TcpStream, LengthDelimitedCodec>>,
    config: &CaSessionConfig,
    router: &BrokerRouter,
    requests: &mut mpsc::Receiver<Vec<u8>>,
    pending: &mut PendingFrames,
    acquired_deliveries: &mut DedupWindow,
) {
    for frame in pending.snapshot() {
        if send_link_frame(&mut writer, frame, config.io_deadline)
            .await
            .is_err()
        {
            return;
        }
    }
    let mut retry = tokio::time::interval(config.retry_period);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retry.tick().await;
    loop {
        tokio::select! {
            request = requests.recv(), if pending.is_empty() && !pending.is_full() => {
                let Some(request) = request else { return };
                let Ok(id) = random_id() else {
                    eprintln!("brokerd event=ca-queue-rejected queue=ca reason=randomness");
                    continue;
                };
                let Ok(encoded) = encode(FrameKind::Request, id, &request) else {
                    eprintln!("brokerd event=ca-queue-rejected queue=ca reason=invalid-frame");
                    continue;
                };
                if pending.insert(id, encoded.clone()).is_err() {
                    eprintln!("brokerd event=ca-queue-rejected queue=ca reason=QueueFull");
                    continue;
                }
                if send_link_frame(&mut writer, encoded, config.io_deadline).await.is_err() {
                    return;
                }
            }
            incoming = reader.next() => {
                let Some(Ok(bytes)) = incoming else { return };
                let Ok(frame) = decode(&bytes) else { return };
                match frame.kind {
                    FrameKind::Ack => {
                        pending.acknowledge(frame.id);
                    }
                    FrameKind::Delivery if acquired_deliveries.contains(frame.id) => {
                        let Ok(ack) = encode(FrameKind::Ack, frame.id, &[]) else { return };
                        if send_link_frame(&mut writer, ack, config.io_deadline).await.is_err() { return; }
                    }
                    FrameKind::Delivery => match router.route_ca_delivery(frame.payload.to_vec()) {
                        Ok(()) => {
                            if acquired_deliveries.insert(frame.id).is_err() { return; }
                            let Ok(ack) = encode(FrameKind::Ack, frame.id, &[]) else { return };
                            if send_link_frame(&mut writer, ack, config.io_deadline).await.is_err() { return; }
                        }
                        Err(error) => {
                            eprintln!("brokerd event=ca-delivery-rejected reason={error}");
                            return;
                        }
                    },
                    _ => return,
                }
            }
            _ = retry.tick(), if !pending.is_empty() => {
                for frame in pending.snapshot() {
                    if send_link_frame(&mut writer, frame, config.io_deadline).await.is_err() { return; }
                }
            }
        }
    }
}

async fn send_link_frame(
    writer: &mut SplitSink<Framed<TcpStream, LengthDelimitedCodec>, bytes::Bytes>,
    frame: Vec<u8>,
    deadline: Duration,
) -> Result<(), ()> {
    match timeout(deadline, writer.send(frame.into())).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}
