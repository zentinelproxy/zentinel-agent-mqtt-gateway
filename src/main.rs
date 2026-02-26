//! MQTT Gateway Agent CLI
//!
//! Standalone agent binary for the Zentinel proxy.
//!
//! Supports both UDS and gRPC transports (v2 protocol).

use anyhow::Result;
use clap::Parser;
use zentinel_agent_mqtt_gateway::{MqttGatewayAgent, MqttGatewayConfig};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// MQTT Gateway Agent for Zentinel
#[derive(Parser, Debug)]
#[command(name = "zentinel-mqtt-agent")]
#[command(author = "Zentinel Contributors")]
#[command(version)]
#[command(about = "MQTT Gateway security agent for Zentinel proxy (Protocol v2)", long_about = None)]
struct Args {
    /// Unix socket path for agent communication (UDS transport)
    #[arg(short, long, default_value = "/tmp/zentinel-mqtt-agent.sock")]
    socket: PathBuf,

    /// gRPC server address (e.g., "0.0.0.0:50051")
    /// When provided, the agent runs as a gRPC server instead of UDS
    #[arg(long)]
    grpc_address: Option<String>,

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

    // Run server based on transport type
    if let Some(grpc_addr) = &args.grpc_address {
        // gRPC transport (v2 protocol)
        info!(
            version = env!("CARGO_PKG_VERSION"),
            protocol = "v2",
            transport = "grpc",
            address = %grpc_addr,
            "Starting MQTT Gateway Agent"
        );

        let addr: std::net::SocketAddr = grpc_addr.parse()
            .map_err(|e| anyhow::anyhow!("Invalid gRPC address '{}': {}", grpc_addr, e))?;

        let server = GrpcAgentServerV2::new("mqtt-gateway", Box::new(agent));
        server.run(addr).await?;
    } else {
        // UDS transport (v2 protocol)
        info!(
            version = env!("CARGO_PKG_VERSION"),
            protocol = "v2",
            transport = "uds",
            socket = %args.socket.display(),
            "Starting MQTT Gateway Agent"
        );

        let server = UdsAgentServerV2::new(
            "mqtt-gateway",
            args.socket,
            Box::new(agent),
        );

        server.run().await?;
    }

    Ok(())
}
