#![forbid(unsafe_code)]

use agent_core::FixedReplayCache;
use app_common::{
    AgentConfig, connect_agent, load_agent, send_agent_frame, send_on_demand_frames, unix_seconds,
};
use clap::Parser;
use protocol_core::{HandlerId, Operator};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};
use transport::{FramedTransport, SystemRandom};
use usecase_models::multi_tenant as model;

const HANDLER: HandlerId = HandlerId(*b"tenant-event-hnd");
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
    tenant_id: String,
    service_id: String,
    #[serde(default = "production")]
    deployment_environment: i64,
    clearance_level: i64,
    region: String,
    #[serde(default = "healthy")]
    service_health: bool,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Publisher,
    Consumer,
}
fn production() -> i64 {
    model::DeploymentEnvironment::Production as i64
}
fn healthy() -> bool {
    true
}
fn invalid(_: usecase_models::ModelError) -> Box<dyn std::error::Error> {
    "invalid multi-tenant configuration".into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config: Config = serde_json::from_slice(&fs::read(args.config)?)?;
    let agent = load_agent(&config.common)?;
    let mut rng = SystemRandom::new()?;
    let role = match config.role {
        Role::Publisher => model::ServiceRole::Publisher,
        Role::Consumer => model::ServiceRole::Consumer,
    };
    let mut environment = model::environment();
    environment
        .bytes(model::TENANT_ID, config.tenant_id.as_bytes())
        .map_err(invalid)?
        .bytes(model::SERVICE_ID, config.service_id.as_bytes())
        .map_err(invalid)?
        .i64(model::DEPLOYMENT_ENVIRONMENT, config.deployment_environment)
        .map_err(invalid)?
        .i64(model::SERVICE_ROLE, role as i64)
        .map_err(invalid)?
        .i64(model::CLEARANCE_LEVEL, config.clearance_level)
        .map_err(invalid)?
        .bool(model::SERVICE_HEALTH, config.service_health)
        .map_err(invalid)?
        .bytes(model::REGION, config.region.as_bytes())
        .map_err(invalid)?;
    match config.role {
        Role::Publisher => publish(&config, &agent, environment.attributes(), &mut rng).await?,
        Role::Consumer => {
            let mut transport = connect_agent(&config.common, agent.id()).await;
            let frame = agent.set_environment(environment.attributes(), &mut rng)?;
            send_agent_frame(&config.common, agent.id(), &mut transport, &frame).await;
            consume(&config, &agent, &mut transport, &mut rng).await?
        }
    }
    Ok(())
}

async fn publish(
    config: &Config,
    agent: &agent_core::Agent,
    environment: &[protocol_core::AttributeRef<'_>],
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("multi-tenant-agent event=request-submitted role=publisher v1-ack=unavailable");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let mut audience = model::audience(config.tenant_id.as_bytes()).map_err(invalid)?;
        audience
            .i64(
                model::SERVICE_ROLE,
                Operator::Eq,
                model::ServiceRole::Consumer as i64,
            )
            .map_err(invalid)?
            .i64(model::CLEARANCE_LEVEL, Operator::Ge, 1)
            .map_err(invalid)?;
        let frame = agent.publish(
            model::DOMAIN_EVENT,
            audience.clauses(),
            line.as_bytes(),
            rng,
        )?;
        let environment = agent.set_environment(environment, rng)?;
        send_on_demand_frames(
            &config.common,
            agent.id(),
            &[environment.as_slice(), frame.as_slice()],
        )
        .await;
        println!("multi-tenant-agent event=publication-submitted");
    }
    Ok(())
}

async fn consume(
    config: &Config,
    agent: &agent_core::Agent,
    transport: &mut FramedTransport,
    rng: &mut SystemRandom,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut subscription = model::subscription(config.tenant_id.as_bytes()).map_err(invalid)?;
    subscription
        .i64(
            model::SERVICE_ROLE,
            Operator::Eq,
            model::ServiceRole::Publisher as i64,
        )
        .map_err(invalid)?;
    let frame = agent.subscribe_permanent_request(
        model::DOMAIN_EVENT,
        HANDLER,
        subscription.clauses(),
        rng,
    )?;
    send_agent_frame(&config.common, agent.id(), transport, &frame).await;
    println!("multi-tenant-agent event=request-submitted role=consumer v1-ack=unavailable");
    let mut replay = FixedReplayCache::<256>::new(600);
    loop {
        let mut frame = match transport.receive().await {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("multi-tenant-agent event=broker-disconnected reason={error}");
                *transport = connect_agent(&config.common, agent.id()).await;
                continue;
            }
        };
        let delivery = match agent.receive(&mut frame, HANDLER, &mut replay, unix_seconds()) {
            Ok(delivery) => delivery,
            Err(error) => {
                eprintln!("multi-tenant-agent event=delivery-rejected reason={error}");
                continue;
            }
        };
        println!(
            "multi-tenant-agent event=delivery-accepted type={}",
            delivery.type_id.0
        );
    }
}
