#![forbid(unsafe_code)]

use agent_core::FixedReplayCache;
use app_common::{
    AgentConfig, connect_agent, decode_hex, load_agent, send_agent_frame, send_on_demand_frames,
    unix_seconds,
};
use clap::Parser;
use protocol_core::{HandlerId, Operator};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};
use transport::{FramedTransport, SystemRandom};
use usecase_models::robot_swarm as model;

const HANDLER: HandlerId = HandlerId(*b"swarm-task-hndlr");

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    common: AgentConfig,
    role: Role,
    swarm_id: String,
    mission_epoch: i64,
    capability: i64,
    payload_capacity: i64,
    #[serde(default = "default_battery")]
    battery_level: i64,
    #[serde(default = "default_true")]
    operational: bool,
    zone: String,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Scout,
    Coordinator,
    Responder,
}
fn default_battery() -> i64 {
    100
}
fn default_true() -> bool {
    true
}
fn invalid(_: usecase_models::ModelError) -> Box<dyn std::error::Error> {
    "invalid robot-swarm configuration".into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config: Config = serde_json::from_slice(&fs::read(args.config)?)?;
    let agent = load_agent(&config.common)?;
    let mut rng = SystemRandom::new()?;
    let role = match config.role {
        Role::Scout => model::RobotRole::Scout,
        Role::Coordinator => model::RobotRole::Coordinator,
        Role::Responder => model::RobotRole::Responder,
    };
    let recipient_id = decode_hex::<16>(&config.common.agent_id)
        .map_err(|_| "agent_id must contain exactly 16 bytes encoded as hexadecimal")?;
    let mut environment = model::environment();
    environment
        .bytes(model::SWARM_ID, config.swarm_id.as_bytes())
        .map_err(invalid)?
        .i64(model::MISSION_EPOCH, config.mission_epoch)
        .map_err(invalid)?
        .i64(model::ROBOT_ROLE, role as i64)
        .map_err(invalid)?
        .i64(model::CAPABILITY, config.capability)
        .map_err(invalid)?
        .i64(model::PAYLOAD_CAPACITY, config.payload_capacity)
        .map_err(invalid)?
        .bool(model::OPERATIONAL, config.operational)
        .map_err(invalid)?
        .i64(model::BATTERY_LEVEL, config.battery_level)
        .map_err(invalid)?
        .bytes(model::ZONE, config.zone.as_bytes())
        .map_err(invalid)?
        .bytes(model::ASSIGNED_TASK, b"none")
        .map_err(invalid)?
        .bytes(model::RECIPIENT_ID, &recipient_id)
        .map_err(invalid)?;
    match config.role {
        Role::Scout => scout(&config, &agent, environment.attributes(), &mut rng).await?,
        Role::Coordinator => {
            let mut transport = connect_agent(&config.common, agent.id()).await;
            let frame = agent.set_environment(environment.attributes(), &mut rng)?;
            send_agent_frame(&config.common, agent.id(), &mut transport, &frame).await;
            coordinator(&config, &agent, &mut transport, &mut rng).await?
        }
        Role::Responder => {
            let mut transport = connect_agent(&config.common, agent.id()).await;
            let frame = agent.set_environment(environment.attributes(), &mut rng)?;
            send_agent_frame(&config.common, agent.id(), &mut transport, &frame).await;
            responder(&config, &agent, &mut transport, &mut rng).await?
        }
    }
    Ok(())
}

async fn scout(
    config: &Config,
    agent: &agent_core::Agent,
    environment: &[protocol_core::AttributeRef<'_>],
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("robot-swarm-agent event=request-submitted role=scout v1-ack=unavailable");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let (type_id, payload) = line
            .strip_prefix("target ")
            .map_or((model::DRONE_TELEMETRY, line.as_bytes()), |value| {
                (model::TARGET_DETECTED, value.as_bytes())
            });
        let mut audience =
            model::audience(config.swarm_id.as_bytes(), config.mission_epoch).map_err(invalid)?;
        let role = if type_id == model::DRONE_TELEMETRY {
            model::RobotRole::Coordinator
        } else {
            model::RobotRole::Responder
        };
        audience
            .i64(model::ROBOT_ROLE, Operator::Eq, role as i64)
            .map_err(invalid)?;
        let frame = agent.publish(type_id, audience.clauses(), payload, rng)?;
        let environment = agent.set_environment(environment, rng)?;
        send_on_demand_frames(
            &config.common,
            agent.id(),
            &[environment.as_slice(), frame.as_slice()],
        )
        .await;
        println!(
            "robot-swarm-agent event=publication-submitted type={}",
            type_id.0
        );
    }
    Ok(())
}

async fn coordinator(
    config: &Config,
    agent: &agent_core::Agent,
    transport: &mut FramedTransport,
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut subscription =
        model::subscription(config.swarm_id.as_bytes(), config.mission_epoch).map_err(invalid)?;
    subscription
        .i64(
            model::ROBOT_ROLE,
            Operator::Eq,
            model::RobotRole::Scout as i64,
        )
        .map_err(invalid)?;
    let frame = agent.subscribe_permanent_request(
        model::DRONE_TELEMETRY,
        HANDLER,
        subscription.clauses(),
        rng,
    )?;
    send_agent_frame(&config.common, agent.id(), transport, &frame).await;
    println!(
        "robot-swarm-agent event=request-submitted role=coordinator v1-ack=unavailable input=<responder-id-hex> <task>"
    );
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdin_open = true;
    let mut replay = FixedReplayCache::<256>::new(600);
    loop {
        tokio::select! {
            frame = transport.receive() => {
                let mut frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => {
                        eprintln!("robot-swarm-agent event=broker-disconnected reason={error}");
                        *transport = connect_agent(&config.common, agent.id()).await;
                        continue;
                    }
                };
                let delivery = match agent.receive(&mut frame, HANDLER, &mut replay, unix_seconds()) {
                    Ok(delivery) => delivery,
                    Err(error) => {
                        eprintln!("robot-swarm-agent event=delivery-rejected reason={error}");
                        continue;
                    }
                };
                println!("robot-swarm-agent event=telemetry-received type={}", delivery.type_id.0);
            }
            line = lines.next_line(), if stdin_open => {
                let Some(line) = line? else {
                    stdin_open = false;
                    continue;
                };
                let (recipient, task) = line.split_once(' ').ok_or("expected recipient-id and task")?;
                let recipient = decode_hex::<16>(recipient)
                    .map_err(|_| "recipient id must contain exactly 16 bytes encoded as hexadecimal")?;
                let mut audience = model::audience(config.swarm_id.as_bytes(), config.mission_epoch).map_err(invalid)?;
                audience.i64(model::ROBOT_ROLE, Operator::Eq, model::RobotRole::Responder as i64).map_err(invalid)?
                    .i64(model::CAPABILITY, Operator::Eq, model::Capability::Transport as i64).map_err(invalid)?
                    .bool(model::OPERATIONAL, Operator::Eq, true).map_err(invalid)?
                    .i64(model::BATTERY_LEVEL, Operator::Ge, 25).map_err(invalid)?
                    .bytes(model::RECIPIENT_ID, Operator::Eq, &recipient).map_err(invalid)?;
                let frame = agent.publish(model::TASK_ASSIGNMENT, audience.clauses(), task.as_bytes(), rng)?;
                send_agent_frame(&config.common, agent.id(), transport, &frame).await;
                println!("robot-swarm-agent event=task-published");
            }
        }
    }
}

async fn responder(
    config: &Config,
    agent: &agent_core::Agent,
    transport: &mut FramedTransport,
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("robot-swarm-agent event=request-submitted role=responder v1-ack=unavailable");
    let mut replay = FixedReplayCache::<256>::new(600);
    loop {
        let mut subscription =
            model::subscription(config.swarm_id.as_bytes(), config.mission_epoch)
                .map_err(invalid)?;
        subscription
            .i64(
                model::ROBOT_ROLE,
                Operator::Eq,
                model::RobotRole::Coordinator as i64,
            )
            .map_err(invalid)?;
        let frame =
            agent.subscribe(model::TASK_ASSIGNMENT, HANDLER, subscription.clauses(), rng)?;
        send_agent_frame(&config.common, agent.id(), transport, &frame).await;
        loop {
            let mut frame = match transport.receive().await {
                Ok(frame) => frame,
                Err(error) => {
                    eprintln!("robot-swarm-agent event=broker-disconnected reason={error}");
                    *transport = connect_agent(&config.common, agent.id()).await;
                    continue;
                }
            };
            let delivery = match agent.receive(&mut frame, HANDLER, &mut replay, unix_seconds()) {
                Ok(delivery) => delivery,
                Err(error) => {
                    eprintln!("robot-swarm-agent event=delivery-rejected reason={error}");
                    continue;
                }
            };
            println!(
                "robot-swarm-agent event=task-received type={}",
                delivery.type_id.0
            );
            break;
        }
    }
}
