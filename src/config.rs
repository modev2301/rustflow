use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// HTTP metrics server address
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,

    /// Collector configurations
    #[serde(default)]
    pub collectors: HashMap<String, String>,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Output configuration
    #[serde(default)]
    pub output: OutputConfig,

    /// Performance configuration
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Mapping configuration for IPFIX
    #[serde(default)]
    pub mapping: MappingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Enable structured logging
    #[serde(default = "default_structured_logging")]
    pub structured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format (json, binary, text)
    #[serde(default = "default_format")]
    pub format: String,

    /// Output producer (raw, proto)
    #[serde(default = "default_producer")]
    pub producer: String,

    /// Output transport (file, kafka)
    #[serde(default = "default_transport")]
    pub transport: String,

    /// Output file path (for file transport)
    #[serde(default = "default_output_file")]
    pub file_path: String,

    /// Kafka configuration (for kafka transport)
    #[serde(default)]
    pub kafka: KafkaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Kafka brokers
    #[serde(default = "default_kafka_brokers")]
    pub brokers: Vec<String>,

    /// Kafka topic
    #[serde(default = "default_kafka_topic")]
    pub topic: String,

    /// Kafka key
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Buffer size for UDP packets
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Number of worker threads
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    /// Batch size for processing
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingConfig {
    /// IPFIX field mappings
    #[serde(default)]
    pub ipfix: Option<IpfixMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfixMapping {
    /// Field mappings
    #[serde(default)]
    pub mapping: Vec<FieldMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Field ID
    pub field: u16,
    /// Destination field name
    pub destination: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let config_str = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&config_str)?;
        Ok(config)
    }

    pub fn load_mapping_config(path: &str) -> Result<MappingConfig> {
        let config_str = std::fs::read_to_string(path)?;
        let config: MappingConfig = serde_yaml::from_str(&config_str)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            metrics_addr: default_metrics_addr(),
            collectors: default_collectors(),
            logging: LoggingConfig::default(),
            output: OutputConfig::default(),
            performance: PerformanceConfig::default(),
            mapping: MappingConfig::default(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            structured: default_structured_logging(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            producer: default_producer(),
            transport: default_transport(),
            file_path: default_output_file(),
            kafka: KafkaConfig::default(),
        }
    }
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: default_kafka_brokers(),
            topic: default_kafka_topic(),
            key: None,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            buffer_size: default_buffer_size(),
            worker_threads: default_worker_threads(),
            batch_size: default_batch_size(),
        }
    }
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            ipfix: None,
        }
    }
}

impl Default for IpfixMapping {
    fn default() -> Self {
        Self {
            mapping: Vec::new(),
        }
    }
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self {
            field: 0,
            destination: String::new(),
        }
    }
}

fn default_metrics_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_collectors() -> HashMap<String, String> {
    let mut collectors = HashMap::new();
    collectors.insert("netflow".to_string(), "0.0.0.0:2055".to_string());
    collectors.insert("sflow".to_string(), "0.0.0.0:6343".to_string());
    collectors
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_structured_logging() -> bool {
    true
}

fn default_format() -> String {
    "json".to_string()
}

fn default_producer() -> String {
    "raw".to_string()
}

fn default_transport() -> String {
    "file".to_string()
}

fn default_output_file() -> String {
    "flows.json".to_string()
}

fn default_kafka_brokers() -> Vec<String> {
    vec!["localhost:9092".to_string()]
}

fn default_kafka_topic() -> String {
    "netflow".to_string()
}

fn default_buffer_size() -> usize {
    9000
}

fn default_worker_threads() -> usize {
    num_cpus::get()
}

fn default_batch_size() -> usize {
    1000
} 