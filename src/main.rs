#![recursion_limit = "256"]

use crate::config::Config;
use crate::decoders::{Decoder, FlowRecord};
use crate::format::Formatter;
use crate::producer::Producer;
use crate::transport::Transporter;
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use std::env;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod decoders;
mod format;
mod producer;
mod transport;
mod utils;

// Remove old CLI-related code and unused functions
// The main function and HTTP handlers are now complete

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration - handle both direct args and args after --
    let args: Vec<String> = env::args().collect();
    info!("Command line arguments: {:?}", args);
    
    let config_path = if args.len() > 1 {
        if args[1] == "--" && args.len() > 2 {
            args[2].clone()
        } else if args[1] == "--config" && args.len() > 2 {
            args[2].clone()
        } else if args[1] == "-config" && args.len() > 2 {
            args[2].clone()
        } else if !args[1].starts_with("-") {
            args[1].clone()
        } else {
            "config.yaml".to_string()
        }
    } else {
        "config.yaml".to_string()
    };
    
    info!("Loading configuration from: {}", config_path);
    
    let config = match Config::load(&config_path) {
        Ok(config) => {
            info!("Successfully loaded configuration from {}", config_path);
            config
        }
        Err(e) => {
            warn!("Failed to load config from {}: {}. Using default config.", config_path, e);
            Config::default()
        }
    };
    
    info!("Starting RustFlow collector...");
    info!("Configuration: {:?}", config);

    // Create channels for communication between components
    let (tx, mut rx) = mpsc::channel::<FlowRecord>(1000);

    // Start collectors
    let _collectors = start_collectors(&config, tx.clone()).await?;

    // Create formatter and producer
    let formatter = create_formatter(&config)?;
    let producer = create_producer(&config, None)?;
    let transporter = create_transporter(&config)?;

    // Start HTTP metrics server
    let app_state = AppState {
        metrics: Arc::new(Metrics::new()),
    };

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(app_state);

    let metrics_addr = config.metrics_addr.parse::<std::net::SocketAddr>()?;
    info!("Starting HTTP metrics server on {}", metrics_addr);
    
    let _metrics_server = tokio::spawn(async move {
        axum::serve(
            tokio::net::TcpListener::bind(&metrics_addr).await.unwrap(),
            app
        ).await.unwrap();
    });

    // Process flow records
    let mut processed_count = 0;
    info!("Starting to process flow records...");
    while let Some(record) = rx.recv().await {
        processed_count += 1;
        info!("Processing flow record #{}: {:?}", processed_count, record);
        
        // Format the record
        let _formatted = formatter.format(&record)?;
        
        // Produce the record
        let produced = producer.produce(&record)?;
        
        // Transport the record
        transporter.send(&produced)?;
        
        if processed_count % 1000 == 0 {
            info!("Processed {} flow records", processed_count);
        }
    }

    Ok(())
}

#[derive(Clone)]
struct AppState {
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct Metrics {
    processed_records: std::sync::atomic::AtomicU64,
    errors: std::sync::atomic::AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self::default()
    }
}

async fn root_handler() -> Json<serde_json::Value> {
    Json(json!({
        "service": "rustflow",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running"
    }))
}

async fn health_handler() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

async fn metrics_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let metrics = json!({
        "processed_records": state.metrics.processed_records.load(std::sync::atomic::Ordering::Relaxed),
        "errors": state.metrics.errors.load(std::sync::atomic::Ordering::Relaxed),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    Json(metrics)
}

async fn start_collectors(
    config: &Config,
    tx: mpsc::Sender<FlowRecord>,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let mut handles = Vec::new();

    for (protocol, addr) in &config.collectors {
        let tx = tx.clone();
        let addr = addr.clone();
        let protocol = protocol.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = start_collector(&protocol, &addr, tx).await {
                error!("Collector error for {}: {}", protocol, e);
            }
        });

        handles.push(handle);
    }

    Ok(handles)
}

async fn start_collector(
    protocol: &str,
    addr: &str,
    tx: mpsc::Sender<FlowRecord>,
) -> Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    info!("Started {} collector on {}", protocol, addr);
    info!("Waiting for {} packets on {}", protocol, addr);

    let mut buf = vec![0u8; 9000]; // Default buffer size
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                info!("Received {} bytes from {} for {}", len, src, protocol);
                // Create a fresh copy of the data to avoid buffer reuse issues
                let data = buf[..len].to_vec();
                // Clear the buffer for next use
                buf.fill(0);
                
                // Debug: print the raw data before conversion
                debug!("Raw data before conversion: {:?}", data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
                
                // Create appropriate decoder based on protocol
                let decoder: Arc<dyn Decoder + Send + Sync> = match protocol {
                    "netflow" => Arc::new(crate::decoders::netflow::NetFlowDecoder::new()),
                    "sflow" => Arc::new(crate::decoders::sflow::SFlowDecoder::new()),
                    _ => {
                        warn!("Unknown protocol: {}", protocol);
                        continue;
                    }
                };

                // Decode the flow records
                let bytes_data = bytes::Bytes::from(data);
                debug!("Data after Bytes conversion: {:?}", bytes_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
                match decoder.decode(bytes_data) {
                    Ok(records) => {
                        info!("Decoded {} flow records from {} packet", records.len(), protocol);
                        for record in records {
                            if let Err(e) = tx.send(record).await {
                                error!("Failed to send record: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to decode {} packet from {}: {}", protocol, src, e);
                    }
                }
            }
            Err(e) => {
                error!("UDP receive error: {}", e);
            }
        }
    }
}

fn create_formatter(config: &Config) -> Result<Arc<dyn Formatter + Send + Sync>> {
    match config.output.format.as_str() {
        "json" => Ok(Arc::new(crate::format::json::JsonFormatter::new())),
        "binary" => Ok(Arc::new(crate::format::binary::BinaryFormatter::new())),
        "text" => Ok(Arc::new(crate::format::text::TextFormatter::new())),
        _ => Err(anyhow::anyhow!("Unsupported format: {}", config.output.format))
    }
}

fn create_producer(config: &Config, mapping_path: Option<&str>) -> Result<Arc<dyn Producer + Send + Sync>> {
    crate::producer::create_producer(config, mapping_path)
}

fn create_transporter(config: &Config) -> Result<Arc<dyn Transporter + Send + Sync>> {
    match config.output.transport.as_str() {
        "file" => Ok(Arc::new(crate::transport::file::FileTransporter::new())),
        "kafka" => Ok(Arc::new(crate::transport::kafka::KafkaTransporter::new())),
        _ => Err(anyhow::anyhow!("Unsupported transport: {}", config.output.transport))
    }
} 