#![allow(dead_code)]

use crate::config::{Config, MappingConfig};
use crate::decoders::FlowRecord;
use anyhow::Result;
use std::sync::Arc;

pub mod proto;
pub mod raw;

pub trait Producer: Send + Sync {
    fn produce(&self, record: &FlowRecord) -> Result<Vec<u8>>;
    fn produce_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>>;
}

pub fn create_producer(config: &Config, mapping_path: Option<&str>) -> Result<Arc<dyn Producer + Send + Sync>> {
    match config.output.producer.as_str() {
        "proto" => {
            let mapping_config = if let Some(path) = mapping_path {
                Config::load_mapping_config(path)?
            } else {
                MappingConfig::default()
            };
            Ok(Arc::new(proto::ProtoProducer::new(mapping_config)))
        }
        "raw" => Ok(Arc::new(raw::RawProducer::new())),
        _ => Err(anyhow::anyhow!("Unsupported producer type: {}", config.output.producer))
    }
}

pub fn get_available_producers() -> Vec<&'static str> {
    vec!["sample", "raw"]
} 