//! MQTT Gateway Agent CLI
//!
//! Standalone agent binary for the Sentinel proxy.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_mqtt_gateway::{MqttGatewayAgent, MqttGatewayConfig};
use sentinel_agent_protocol::AgentServer;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// MQTT Gateway Agent for Sentinel
#[derive(Parser, Debug)]
#[command(name = "sentinel-mqtt-agent")]
#[command(author = "Sentinel Contributors")]
#[command(version)]
#[command(about = "MQTT Gateway security agent for Sentinel proxy", long_about = None)]
struct Args {
    /// Unix socket path for agent communication
    #[arg(short, long, default_value = "/tmp/sentinel-mqtt-agent.sock")]
    socket: PathBuf,

    /// Configuration file path (JSON)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable JSON log format
    #[arg(long)]
    json_logs: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    if args.json_logs {
        fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    } else {
        fmt()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = %args.socket.display(),
        "Starting MQTT Gateway Agent"
    );

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        info!(path = %config_path.display(), "Loading configuration from file");
        let content = std::fs::read_to_string(config_path)?;
        serde_json::from_str(&content)?
    } else {
        MqttGatewayConfig::default()
    };

    // Create agent
    let agent = MqttGatewayAgent::with_config(config)?;

    info!("Agent initialized, starting server");

    // Create and run server
    let server = AgentServer::new(
        "mqtt-gateway",
        args.socket,
        Box::new(agent),
    );

    server.run().await?;

    Ok(())
}
