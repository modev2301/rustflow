#![allow(dead_code)]

pub mod json;
pub mod binary;
pub mod text;

use crate::decoders::FlowRecord;
use anyhow::Result;
use std::sync::Arc;

pub trait Formatter: Send + Sync {
    fn format(&self, record: &FlowRecord) -> Result<Vec<u8>>;
    fn format_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>>;
}

pub fn create_formatter(format_type: &str) -> Result<Arc<dyn Formatter>> {
    match format_type {
        "json" => Ok(Arc::new(json::JsonFormatter::new())),
        "bin" | "binary" => Ok(Arc::new(binary::BinaryFormatter::new())),
        "text" => Ok(Arc::new(text::TextFormatter::new())),
        _ => Err(anyhow::anyhow!("Unknown format type: {}", format_type)),
    }
}

pub fn get_available_formats() -> Vec<&'static str> {
    vec!["json", "bin", "text"]
} 