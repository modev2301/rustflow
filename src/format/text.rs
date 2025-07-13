use crate::decoders::{FlowRecord, FlowType};
use crate::format::Formatter;
use anyhow::Result;
use std::fmt::Write;

pub struct TextFormatter {
    include_timestamps: bool,
    include_metadata: bool,
}

impl TextFormatter {
    pub fn new() -> Self {
        Self {
            include_timestamps: true,
            include_metadata: true,
        }
    }

    pub fn _with_timestamps(mut self, include: bool) -> Self {
        self.include_timestamps = include;
        self
    }

    pub fn _with_metadata(mut self, include: bool) -> Self {
        self.include_metadata = include;
        self
    }

    fn flow_type_to_string(&self, flow_type: &FlowType) -> &'static str {
        match flow_type {
            FlowType::SFlow5 => "SFLOW_5",
            FlowType::NetFlowV5 => "NETFLOW_V5",
            FlowType::NetFlowV9 => "NETFLOW_V9",
            FlowType::IPFIX => "IPFIX",
        }
    }

    fn protocol_to_string(&self, proto: u32) -> &'static str {
        match proto {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            47 => "GRE",
            58 => "ICMPv6",
            _ => "UNKNOWN",
        }
    }

    fn format_address(&self, bytes: &[u8]) -> String {
        match bytes.len() {
            4 => {
                if let Ok(ip) = crate::decoders::utils::bytes_to_ipv4(bytes) {
                    ip.to_string()
                } else {
                    format!("{:?}", bytes)
                }
            }
            16 => {
                if let Ok(ip) = crate::decoders::utils::bytes_to_ipv6(bytes) {
                    ip.to_string()
                } else {
                    format!("{:?}", bytes)
                }
            }
            _ => format!("{:?}", bytes),
        }
    }

    fn format_mac(&self, mac: u64) -> String {
        crate::decoders::utils::format_mac(mac)
    }

    fn format_timestamp(&self, timestamp_ns: u64) -> String {
        if timestamp_ns == 0 {
            return "0".to_string();
        }
        
        let seconds = timestamp_ns / 1_000_000_000;
        let nanos = timestamp_ns % 1_000_000_000;
        
        if let Some(datetime) = chrono::DateTime::from_timestamp(seconds as i64, nanos as u32) {
            datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
        } else {
            format!("{}", timestamp_ns)
        }
    }

    fn record_to_text(&self, record: &FlowRecord) -> Result<String> {
        let mut text = String::new();
        
        // Basic flow information
        writeln!(text, "Flow Record:")?;
        writeln!(text, "  Type: {}", self.flow_type_to_string(&record.flow_type))?;
        writeln!(text, "  Sequence: {}", record.sequence_num)?;
        writeln!(text, "  Sampling Rate: {}", record.sampling_rate)?;
        
        if self.include_timestamps {
            writeln!(text, "  Time Received: {}", self.format_timestamp(record.time_received_ns))?;
            writeln!(text, "  Flow Start: {}", self.format_timestamp(record.time_flow_start_ns))?;
            writeln!(text, "  Flow End: {}", self.format_timestamp(record.time_flow_end_ns))?;
        }
        
        // Traffic information
        writeln!(text, "  Bytes: {}", record.bytes)?;
        writeln!(text, "  Packets: {}", record.packets)?;
        
        // Address information
        writeln!(text, "  Source: {}:{}", self.format_address(&record.src_addr), record.src_port)?;
        writeln!(text, "  Destination: {}:{}", self.format_address(&record.dst_addr), record.dst_port)?;
        
        // Protocol information
        writeln!(text, "  Protocol: {} ({})", self.protocol_to_string(record.proto), record.proto)?;
        writeln!(text, "  EtherType: 0x{:04x}", record.etype)?;
        
        // Interface information
        if record.in_if != 0 {
            writeln!(text, "  Input Interface: {}", record.in_if)?;
        }
        if record.out_if != 0 {
            writeln!(text, "  Output Interface: {}", record.out_if)?;
        }
        
        // MAC addresses
        if record.src_mac != 0 {
            writeln!(text, "  Source MAC: {}", self.format_mac(record.src_mac))?;
        }
        if record.dst_mac != 0 {
            writeln!(text, "  Destination MAC: {}", self.format_mac(record.dst_mac))?;
        }
        
        // VLAN information
        if record.vlan_id != 0 {
            writeln!(text, "  VLAN ID: {}", record.vlan_id)?;
        }
        if record.src_vlan != 0 {
            writeln!(text, "  Source VLAN: {}", record.src_vlan)?;
        }
        if record.dst_vlan != 0 {
            writeln!(text, "  Destination VLAN: {}", record.dst_vlan)?;
        }
        
        // IP flags and options
        if record.ip_tos != 0 {
            writeln!(text, "  IP ToS: 0x{:02x}", record.ip_tos)?;
        }
        if record.ip_ttl != 0 {
            writeln!(text, "  IP TTL: {}", record.ip_ttl)?;
        }
        if record.ip_flags != 0 {
            writeln!(text, "  IP Flags: 0x{:02x}", record.ip_flags)?;
        }
        if record.tcp_flags != 0 {
            writeln!(text, "  TCP Flags: 0x{:02x}", record.tcp_flags)?;
        }
        
        // ICMP information
        if record.icmp_type != 0 {
            writeln!(text, "  ICMP Type: {}", record.icmp_type)?;
        }
        if record.icmp_code != 0 {
            writeln!(text, "  ICMP Code: {}", record.icmp_code)?;
        }
        
        // IPv6 specific
        if record.ipv6_flow_label != 0 {
            writeln!(text, "  IPv6 Flow Label: 0x{:05x}", record.ipv6_flow_label)?;
        }
        
        // Fragment information
        if record.fragment_id != 0 {
            writeln!(text, "  Fragment ID: {}", record.fragment_id)?;
        }
        if record.fragment_offset != 0 {
            writeln!(text, "  Fragment Offset: {}", record.fragment_offset)?;
        }
        
        // AS information
        if record.src_as != 0 {
            writeln!(text, "  Source AS: {}", record.src_as)?;
        }
        if record.dst_as != 0 {
            writeln!(text, "  Destination AS: {}", record.dst_as)?;
        }
        
        // Next hop
        if !record.next_hop.is_empty() {
            writeln!(text, "  Next Hop: {}", self.format_address(&record.next_hop))?;
        }
        if record.next_hop_as != 0 {
            writeln!(text, "  Next Hop AS: {}", record.next_hop_as)?;
        }
        
        // Network information
        if record.src_net != 0 {
            writeln!(text, "  Source Net: /{}", record.src_net)?;
        }
        if record.dst_net != 0 {
            writeln!(text, "  Destination Net: /{}", record.dst_net)?;
        }
        
        // BGP information
        if !record.bgp_next_hop.is_empty() {
            writeln!(text, "  BGP Next Hop: {}", self.format_address(&record.bgp_next_hop))?;
        }
        if !record.bgp_communities.is_empty() {
            writeln!(text, "  BGP Communities: {:?}", record.bgp_communities)?;
        }
        if !record.as_path.is_empty() {
            writeln!(text, "  AS Path: {:?}", record.as_path)?;
        }
        
        // MPLS information
        if !record.mpls_label.is_empty() {
            writeln!(text, "  MPLS Labels: {:?}", record.mpls_label)?;
        }
        if !record.mpls_ttl.is_empty() {
            writeln!(text, "  MPLS TTLs: {:?}", record.mpls_ttl)?;
        }
        if !record.mpls_ip.is_empty() {
            writeln!(text, "  MPLS IPs: {:?}", record.mpls_ip.iter().map(|ip| self.format_address(ip)).collect::<Vec<_>>())?;
        }
        
        // Observation information
        if record.observation_domain_id != 0 {
            writeln!(text, "  Observation Domain ID: {}", record.observation_domain_id)?;
        }
        if record.observation_point_id != 0 {
            writeln!(text, "  Observation Point ID: {}", record.observation_point_id)?;
        }
        
        // Layer stack
        if !record.layer_stack.is_empty() {
            writeln!(text, "  Layer Stack: {:?}", record.layer_stack.iter().map(|l| self.layer_stack_to_string(l)).collect::<Vec<_>>())?;
        }
        if !record.layer_size.is_empty() {
            writeln!(text, "  Layer Sizes: {:?}", record.layer_size)?;
        }
        
        // IPv6 routing header
        if !record.ipv6_routing_header_addresses.is_empty() {
            writeln!(text, "  IPv6 Routing Header Addresses: {:?}", record.ipv6_routing_header_addresses.iter().map(|addr| self.format_address(addr)).collect::<Vec<_>>())?;
        }
        if record.ipv6_routing_header_seg_left != 0 {
            writeln!(text, "  IPv6 Routing Header Segments Left: {}", record.ipv6_routing_header_seg_left)?;
        }
        
        // Enterprise fields
        if !record.enterprise_fields.is_empty() {
            writeln!(text, "  Enterprise Fields:")?;
            for ((pen, field_type), data) in &record.enterprise_fields {
                let vendor_name = match pen {
                    9 => "Cisco",
                    23867 => "Silver Peak",
                    _ => "Unknown",
                };
                writeln!(text, "    {} (PEN={}, Type={}): {}", vendor_name, pen, field_type, hex::encode(data))?;
            }
        }
        
        // Metadata
        if self.include_metadata && !record.sampler_address.is_empty() {
            writeln!(text, "  Sampler Address: {}", self.format_address(&record.sampler_address))?;
        }
        
        writeln!(text)?;
        Ok(text)
    }

    fn layer_stack_to_string(&self, layer: &str) -> String {
        layer.to_string()
    }
}

impl Formatter for TextFormatter {
    fn format(&self, record: &FlowRecord) -> Result<Vec<u8>> {
        let text = self.record_to_text(record)?;
        Ok(text.into_bytes())
    }

    fn format_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>> {
        let mut text = String::new();
        
        for record in records {
            text.push_str(&self.record_to_text(record)?);
        }
        
        Ok(text.into_bytes())
    }
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self::new()
    }
} 