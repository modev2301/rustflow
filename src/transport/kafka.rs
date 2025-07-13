use crate::transport::Transporter;
use anyhow::Result;
use tracing::warn;

pub struct KafkaTransporter {
    _brokers: Vec<String>,
    topic: String,
    _key: Option<String>,
    _compression: String,
}

impl KafkaTransporter {
    pub fn new() -> Self {
        Self {
            _brokers: vec!["localhost:9092".to_string()],
            topic: "flows".to_string(),
            _key: None,
            _compression: "none".to_string(),
        }
    }

    pub fn _with_brokers(mut self, brokers: Vec<String>) -> Self {
        self._brokers = brokers;
        self
    }

    pub fn _with_topic(mut self, topic: String) -> Self {
        self.topic = topic;
        self
    }

    pub fn _with_key(mut self, key: Option<String>) -> Self {
        self._key = key;
        self
    }

    pub fn _with_compression(mut self, compression: String) -> Self {
        self._compression = compression;
        self
    }
}

impl Transporter for KafkaTransporter {
    fn send(&self, data: &[u8]) -> Result<()> {
        // For now, we'll just log that we would send to Kafka
        // In a real implementation, you'd use rdkafka or similar
        warn!("Would send {} bytes to Kafka topic '{}'", data.len(), self.topic);
        Ok(())
    }

    fn send_batch(&self, data: &[Vec<u8>]) -> Result<()> {
        for item in data {
            self.send(item)?;
        }
        Ok(())
    }
}

impl Default for KafkaTransporter {
    fn default() -> Self {
        Self::new()
    }
} 