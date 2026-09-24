#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

use agent_core::FixedReplayCache;
use app_common::{
    AgentConfig, connect_agent, load_agent, send_agent_frame, send_on_demand_frames, unix_seconds,
};
use clap::Parser;
use protocol_core::{HandlerId, Operator};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use transport::{FramedTransport, SystemRandom};
use usecase_models::smart_building as model;

const HANDLER: HandlerId = HandlerId(*b"building-handler");

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
    building_id: String,
    floor_id: Option<i64>,
    alert_zone: String,
    #[serde(default = "default_true")]
    operational: bool,
    #[serde(default)]
    temperature_centi_celsius: i64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Sensor,
    ControlPanel,
    MaintenanceTerminal,
}

fn default_true() -> bool {
    true
}
fn invalid(_: usecase_models::ModelError) -> Box<dyn std::error::Error> {
    "invalid smart-building configuration".into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config: Config = serde_json::from_slice(&fs::read(args.config)?)?;
    let agent = load_agent(&config.common)?;
    let mut rng = SystemRandom::new()?;

    let mut environment = model::environment();
    environment
        .bytes(model::BUILDING_ID, config.building_id.as_bytes())
        .map_err(invalid)?
        .bytes(model::ALERT_ZONE, config.alert_zone.as_bytes())
        .map_err(invalid)?
        .bool(model::OPERATIONAL, config.operational)
        .map_err(invalid)?;
    match config.role {
        Role::Sensor => {
            environment
                .i64(
                    model::FLOOR_ID,
                    config.floor_id.ok_or("sensor requires floor_id")?,
                )
                .map_err(invalid)?
                .i64(model::DEVICE_CLASS, model::DeviceClass::Sensor as i64)
                .map_err(invalid)?
                .bool(model::CERTIFIED_DEVICE, true)
                .map_err(invalid)?
                .i64(model::TEMPERATURE, config.temperature_centi_celsius)
                .map_err(invalid)?;
        }
        Role::ControlPanel => {
            environment
                .i64(model::DEVICE_CLASS, model::DeviceClass::ControlPanel as i64)
                .map_err(invalid)?
                .i64(model::USER_ROLE, model::UserRole::ControlOperator as i64)
                .map_err(invalid)?;
        }
        Role::MaintenanceTerminal => {
            environment
                .i64(
                    model::DEVICE_CLASS,
                    model::DeviceClass::MaintenanceTerminal as i64,
                )
                .map_err(invalid)?
                .i64(
                    model::USER_ROLE,
                    model::UserRole::MaintenanceOperator as i64,
                )
                .map_err(invalid)?;
        }
    }
    match config.role {
        Role::Sensor => run_sensor(&config, &agent, environment.attributes(), &mut rng).await?,
        Role::ControlPanel => {
            let mut transport = connect_agent(&config.common, agent.id()).await;
            let frame = agent.set_environment(environment.attributes(), &mut rng)?;
            send_agent_frame(&config.common, agent.id(), &mut transport, &frame).await;
            run_panel(&config, &agent, &mut transport, &mut rng).await?
        }
        Role::MaintenanceTerminal => {
            let mut transport = connect_agent(&config.common, agent.id()).await;
            let frame = agent.set_environment(environment.attributes(), &mut rng)?;
            send_agent_frame(&config.common, agent.id(), &mut transport, &frame).await;
            run_maintenance(&config, &agent, &mut transport, &mut rng).await?
        }
    }
    Ok(())
}

async fn run_sensor(
    config: &Config,
    agent: &agent_core::Agent,
    environment: &[protocol_core::AttributeRef<'_>],
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("smart-building-agent event=request-submitted role=sensor v1-ack=unavailable");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let temperature: i64 = line.trim().parse()?;
        let mut audience = model::audience(config.building_id.as_bytes()).map_err(invalid)?;
        audience
            .i64(
                model::USER_ROLE,
                Operator::Eq,
                model::UserRole::ControlOperator as i64,
            )
            .map_err(invalid)?;
        let frame = agent.publish(
            model::SENSOR_READING,
            audience.clauses(),
            &temperature.to_be_bytes(),
            rng,
        )?;
        let environment = agent.set_environment(environment, rng)?;
        send_on_demand_frames(
            &config.common,
            agent.id(),
            &[environment.as_slice(), frame.as_slice()],
        )
        .await;
        println!(
            "smart-building-agent event=publication-submitted type={}",
            model::SENSOR_READING.0
        );
    }
    Ok(())
}

async fn run_panel(
    config: &Config,
    agent: &agent_core::Agent,
    transport: &mut FramedTransport,
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut subscription = model::subscription(config.building_id.as_bytes()).map_err(invalid)?;
    subscription
        .bool(model::CERTIFIED_DEVICE, Operator::Eq, true)
        .map_err(invalid)?;
    let frame = agent.subscribe_permanent_request(
        model::SENSOR_READING,
        HANDLER,
        subscription.clauses(),
        rng,
    )?;
    send_agent_frame(&config.common, agent.id(), transport, &frame).await;
    println!("smart-building-agent event=request-submitted role=control-panel v1-ack=unavailable");
    let mut replay = FixedReplayCache::<256>::new(600);
    loop {
        let mut frame = match transport.receive().await {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("smart-building-agent event=broker-disconnected reason={error}");
                *transport = connect_agent(&config.common, agent.id()).await;
                continue;
            }
        };
        let delivery = match agent.receive(&mut frame, HANDLER, &mut replay, unix_seconds()) {
            Ok(delivery) => delivery,
            Err(error) => {
                eprintln!("smart-building-agent event=delivery-rejected reason={error}");
                continue;
            }
        };
        println!(
            "smart-building-agent event=delivery-accepted type={}",
            delivery.type_id.0
        );
    }
}

async fn run_maintenance(
    config: &Config,
    agent: &agent_core::Agent,
    transport: &mut FramedTransport,
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    let subscription = model::subscription(config.building_id.as_bytes()).map_err(invalid)?;
    let frame = agent.subscribe_permanent_request(
        model::MAINTENANCE_COMMAND,
        HANDLER,
        subscription.clauses(),
        rng,
    )?;
    send_agent_frame(&config.common, agent.id(), transport, &frame).await;
    println!(
        "smart-building-agent event=request-submitted role=maintenance-terminal v1-ack=unavailable"
    );
    let mut replay = FixedReplayCache::<256>::new(600);
    loop {
        let mut frame = match transport.receive().await {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("smart-building-agent event=broker-disconnected reason={error}");
                *transport = connect_agent(&config.common, agent.id()).await;
                continue;
            }
        };
        let delivery = match agent.receive(&mut frame, HANDLER, &mut replay, unix_seconds()) {
            Ok(delivery) => delivery,
            Err(error) => {
                eprintln!("smart-building-agent event=delivery-rejected reason={error}");
                continue;
            }
        };
        println!(
            "smart-building-agent event=delivery-accepted type={}",
            delivery.type_id.0
        );
    }
}
