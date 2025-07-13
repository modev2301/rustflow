#![allow(dead_code)]

pub mod file;
pub mod kafka;

use anyhow::Result;
use std::sync::Arc;

pub trait Transporter: Send + Sync {
    fn send(&self, data: &[u8]) -> Result<()>;
    fn send_batch(&self, data: &[Vec<u8>]) -> Result<()>;
}

pub fn create_transporter(transport_type: &str) -> Result<Arc<dyn Transporter>> {
    match transport_type {
        "file" => Ok(Arc::new(file::FileTransporter::new())),
        "kafka" => Ok(Arc::new(kafka::KafkaTransporter::new())),
        _ => Err(anyhow::anyhow!("Unknown transport type: {}", transport_type)),
    }
}

pub fn get_available_transports() -> Vec<&'static str> {
    vec!["file", "kafka"]
} 