# RustFlow

A high-performance NetFlow/IPFIX/sFlow collector written in Rust, designed to replace GoFlow2 with better performance and memory safety.

## Features

### ✅ Implemented
- **NetFlow Support**: v5, v9, and IPFIX protocols
- **sFlow Support**: v5 with expanded flow and counter samples
- **Enterprise Fields**: Support for vendor-specific fields (Cisco, Silver Peak, etc.)
- **Async Architecture**: Built on Tokio for high-performance I/O
- **Modular Design**: Pluggable decoders, formatters, producers, and transporters
- **HTTP Metrics Server**: Health checks and metrics endpoints
- **Configuration**: YAML-based configuration with sensible defaults
- **Logging**: Structured logging with configurable levels
- **Error Handling**: Comprehensive error handling with anyhow/thiserror

### 🔄 In Progress
- Performance benchmarks and optimization
- Kafka transport implementation
- Additional enterprise field vendors
- Comprehensive test coverage

## Quick Start

### Prerequisites
- Rust 1.70+ and Cargo
- Network devices configured to send NetFlow/sFlow to your collector

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/modev2301/rustflow.git
   cd rustflow
   ```

2. **Build the project**:
   ```bash
   cargo build --release
   ```

3. **Run with default configuration**:
   ```bash
   ./target/release/rustflow
   ```

### Configuration

Create a `config.yaml` file:

```yaml
# HTTP metrics server address
metrics_addr: "127.0.0.1:8080"

# Collector configurations
collectors:
  netflow: "0.0.0.0:2055"
  sflow: "0.0.0.0:6343"

# Logging configuration
logging:
  level: "info"  # debug, info, warn, error
  structured: true

# Output configuration
output:
  format: "json"  # json, binary, text
  producer: "raw"  # raw, proto
  transport: "file"  # file, kafka
  file_path: "flows.json"
  kafka:
    brokers:
      - "localhost:9092"
    topic: "netflow"
    key: null

# Performance configuration
performance:
  buffer_size: 9000
  worker_threads: 4
  batch_size: 1000
```

### Command Line Usage

```bash
# Run with custom config file
rustflow --config my-config.yaml

# Enable debug logging
rustflow --debug

# Add additional collectors via command line
rustflow --listen netflow:0.0.0.0:2056 --listen sflow:0.0.0.0:6344

# Show help
rustflow --help
```

## Architecture

### Core Components

1. **Decoders**: Parse NetFlow/sFlow packets into structured data
   - `NetFlowDecoder`: Handles NetFlow v5, v9, and IPFIX
   - `SFlowDecoder`: Handles sFlow v5 with various sample types

2. **Formatters**: Convert flow records to different output formats
   - `JsonFormatter`: JSON output with metadata
   - `BinaryFormatter`: Protobuf binary format
   - `TextFormatter`: Human-readable text format

3. **Producers**: Process and transform flow records
   - `RawProducer`: Raw flow data
   - `ProtoProducer`: Protobuf-encoded data

4. **Transporters**: Send data to various destinations
   - `FileTransporter`: Write to files
   - `KafkaTransporter`: Send to Kafka topics

### Enterprise Fields Support

RustFlow supports vendor-specific enterprise fields through NetFlow v9 and IPFIX:

#### Supported Vendors
- **Cisco (PEN: 9)**: MPLS label fields, QoS information
- **Silver Peak (PEN: 23867)**: WAN optimization metrics

#### Enterprise Field Output
Enterprise fields are included in all output formats:

**JSON Format**:
```json
{
  "type": "NETFLOW_V9",
  "src_addr": "192.168.1.1",
  "dst_addr": "192.168.1.2",
  "enterprise_fields": {
    "enterprise_9_1": "deadbeef",
    "enterprise_23867_1": "12345678"
  }
}
```

**Text Format**:
```
Flow Record:
  Type: NETFLOW_V9
  Source: 192.168.1.1:80
  Destination: 192.168.1.2:443
  Enterprise Fields:
    Cisco (PEN=9, Type=1): deadbeef
    Silver Peak (PEN=23867, Type=1): 12345678
```

**Binary Format**: Enterprise fields are included in the protobuf message structure.

### Data Flow

```
Network Device → UDP Socket → Decoder → Formatter → Producer → Transporter → Output
```

## Performance

### Benchmarks

Run performance benchmarks:

```bash
cargo bench
```

### Performance Characteristics

- **Memory Usage**: Significantly lower than GoFlow2 due to Rust's zero-cost abstractions
- **CPU Usage**: Optimized for high-throughput scenarios
- **Latency**: Sub-millisecond packet processing
- **Throughput**: Designed to handle 100k+ flows/second

## API Endpoints

### Health Check
```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Metrics
```bash
curl http://localhost:8080/metrics
```

Response:
```json
{
  "rustflow_packets_received_total": 12345,
  "rustflow_flows_processed_total": 67890,
  "rustflow_errors_total": 0,
  "rustflow_uptime_seconds": 3600
}
```

### Root Endpoint
```bash
curl http://localhost:8080/
```

Response:
```json
{
  "name": "rustflow",
  "version": "0.1.0",
  "description": "A NetFlow/IPFIX/sFlow collector in Rust"
}
```

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Adding Enterprise Field Support

To add support for a new vendor's enterprise fields:

1. **Add the PEN (Private Enterprise Number)** to the vendor mapping in `src/decoders/netflow.rs`:
   ```rust
   match enterprise_id {
       9 => self.handle_cisco_enterprise_fields(record, field_type, data)?,
       23867 => self.handle_silverpeak_enterprise_fields(record, field_type, data)?,
       12345 => self.handle_new_vendor_enterprise_fields(record, field_type, data)?, // Add here
       _ => {
           debug!("Unknown enterprise: PEN={}, field_type={}", enterprise_id, field_type);
       }
   }
   ```

2. **Implement the handler function**:
   ```rust
   fn handle_new_vendor_enterprise_fields(&self, record: &mut FlowRecord, field_type: u16, data: &[u8]) -> Result<()> {
       match field_type {
           1 => {
               // Handle field type 1
               let value = self.read_u32(data)?;
               record.enterprise_fields.insert((12345, 1), data.to_vec());
               debug!("New Vendor Field 1: {}", value);
           }
           _ => {
               debug!("Unknown New Vendor enterprise field: {}", field_type);
           }
       }
       Ok(())
   }
   ```

3. **Update the text formatter** to include the vendor name in `src/format/text.rs`:
   ```rust
   let vendor_name = match pen {
       9 => "Cisco",
       23867 => "Silver Peak",
       12345 => "New Vendor", // Add here
       _ => "Unknown",
   };
   ```

### Project Structure

```
rustflow/
├── src/
│   ├── main.rs              # Application entry point
│   ├── lib.rs               # Library exports
│   ├── config.rs            # Configuration management
│   ├── decoders/            # Protocol decoders
│   │   ├── mod.rs
│   │   ├── netflow.rs       # NetFlow/IPFIX decoder
│   │   ├── sflow.rs         # sFlow decoder
│   │   └── utils.rs         # Decoder utilities
│   ├── format/              # Output formatters
│   │   ├── mod.rs
│   │   ├── json.rs          # JSON formatter
│   │   ├── binary.rs        # Binary formatter
│   │   └── text.rs          # Text formatter
│   ├── producer/            # Data producers
│   │   ├── mod.rs
│   │   ├── raw.rs           # Raw producer
│   │   └── proto.rs         # Protobuf producer
│   └── transport/           # Data transporters
│       ├── mod.rs
│       ├── file.rs          # File transport
│       └── kafka.rs         # Kafka transport
├── benches/                 # Performance benchmarks
├── proto/                   # Protocol buffer definitions
├── config.yaml             # Sample configuration
└── Cargo.toml              # Dependencies and metadata
```

## Comparison with GoFlow2

| Feature | GoFlow2 | RustFlow |
|---------|---------|----------|
| Language | Go | Rust |
| Memory Safety | GC | Zero-cost abstractions |
| Performance | Good | Excellent |
| Memory Usage | Higher | Lower |
| Concurrency | Goroutines | Async/await |
| Type Safety | Good | Excellent |
| Compile Time | Fast | Slower |
| Runtime | GC | No GC |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Rust coding standards
- Add tests for new features
- Update documentation
- Run benchmarks for performance-critical changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [GoFlow2](https://github.com/netsampler/goflow2)
- Built with [Tokio](https://tokio.rs/) for async runtime
- Uses [Criterion](https://github.com/bheisler/criterion.rs) for benchmarking

## Roadmap

- [ ] Complete IPFIX template handling
- [ ] Kafka transport implementation
- [ ] Docker containerization
- [ ] Kubernetes deployment examples
- [ ] Prometheus metrics integration
- [ ] Advanced filtering and aggregation
- [ ] Plugin system for custom decoders
- [ ] Web UI for monitoring and configuration
