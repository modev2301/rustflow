use crate::decoders::{FlowRecord, FlowType};
use crate::format::Formatter;
use anyhow::Result;
use serde_json::Value;

pub struct JsonFormatter {
    include_metadata: bool,
}

impl JsonFormatter {
    pub fn new() -> Self {
        Self {
            include_metadata: true,
        }
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

    fn layer_stack_to_string(&self, layer: &str) -> String {
        layer.to_string()
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

    fn record_to_json(&self, record: &FlowRecord) -> Value {
        let mut map = serde_json::Map::new();
        
        map.insert("type".to_string(), Value::String(self.flow_type_to_string(&record.flow_type).to_string()));
        map.insert("time_received_ns".to_string(), Value::Number(serde_json::Number::from(record.time_received_ns)));
        map.insert("sequence_num".to_string(), Value::Number(serde_json::Number::from(record.sequence_num)));
        map.insert("sampling_rate".to_string(), Value::Number(serde_json::Number::from(record.sampling_rate)));
        map.insert("time_flow_start_ns".to_string(), Value::Number(serde_json::Number::from(record.time_flow_start_ns)));
        map.insert("time_flow_end_ns".to_string(), Value::Number(serde_json::Number::from(record.time_flow_end_ns)));
        map.insert("bytes".to_string(), Value::Number(serde_json::Number::from(record.bytes)));
        map.insert("packets".to_string(), Value::Number(serde_json::Number::from(record.packets)));
        map.insert("src_addr".to_string(), Value::String(self.format_address(&record.src_addr)));
        map.insert("dst_addr".to_string(), Value::String(self.format_address(&record.dst_addr)));
        map.insert("etype".to_string(), Value::Number(serde_json::Number::from(record.etype)));
        map.insert("proto".to_string(), Value::Number(serde_json::Number::from(record.proto)));
        map.insert("src_port".to_string(), Value::Number(serde_json::Number::from(record.src_port)));
        map.insert("dst_port".to_string(), Value::Number(serde_json::Number::from(record.dst_port)));
        map.insert("in_if".to_string(), Value::Number(serde_json::Number::from(record.in_if)));
        map.insert("out_if".to_string(), Value::Number(serde_json::Number::from(record.out_if)));
        map.insert("src_mac".to_string(), Value::String(self.format_mac(record.src_mac)));
        map.insert("dst_mac".to_string(), Value::String(self.format_mac(record.dst_mac)));
        map.insert("src_vlan".to_string(), Value::Number(serde_json::Number::from(record.src_vlan)));
        map.insert("dst_vlan".to_string(), Value::Number(serde_json::Number::from(record.dst_vlan)));
        map.insert("vlan_id".to_string(), Value::Number(serde_json::Number::from(record.vlan_id)));
        map.insert("ip_tos".to_string(), Value::Number(serde_json::Number::from(record.ip_tos)));
        map.insert("forwarding_status".to_string(), Value::Number(serde_json::Number::from(record.forwarding_status)));
        map.insert("ip_ttl".to_string(), Value::Number(serde_json::Number::from(record.ip_ttl)));
        map.insert("ip_flags".to_string(), Value::Number(serde_json::Number::from(record.ip_flags)));
        map.insert("tcp_flags".to_string(), Value::Number(serde_json::Number::from(record.tcp_flags)));
        map.insert("icmp_type".to_string(), Value::Number(serde_json::Number::from(record.icmp_type)));
        map.insert("icmp_code".to_string(), Value::Number(serde_json::Number::from(record.icmp_code)));
        map.insert("ipv6_flow_label".to_string(), Value::Number(serde_json::Number::from(record.ipv6_flow_label)));
        map.insert("fragment_id".to_string(), Value::Number(serde_json::Number::from(record.fragment_id)));
        map.insert("fragment_offset".to_string(), Value::Number(serde_json::Number::from(record.fragment_offset)));
        map.insert("src_as".to_string(), Value::Number(serde_json::Number::from(record.src_as)));
        map.insert("dst_as".to_string(), Value::Number(serde_json::Number::from(record.dst_as)));
        map.insert("next_hop".to_string(), Value::String(self.format_address(&record.next_hop)));
        map.insert("next_hop_as".to_string(), Value::Number(serde_json::Number::from(record.next_hop_as)));
        map.insert("src_net".to_string(), Value::Number(serde_json::Number::from(record.src_net)));
        map.insert("dst_net".to_string(), Value::Number(serde_json::Number::from(record.dst_net)));
        map.insert("bgp_next_hop".to_string(), Value::String(self.format_address(&record.bgp_next_hop)));
        
        // Add arrays
        let bgp_communities: Vec<Value> = record.bgp_communities.iter().map(|&x| Value::Number(serde_json::Number::from(x))).collect();
        map.insert("bgp_communities".to_string(), Value::Array(bgp_communities));
        
        let as_path: Vec<Value> = record.as_path.iter().map(|&x| Value::Number(serde_json::Number::from(x))).collect();
        map.insert("as_path".to_string(), Value::Array(as_path));
        
        let mpls_ttl: Vec<Value> = record.mpls_ttl.iter().map(|&x| Value::Number(serde_json::Number::from(x))).collect();
        map.insert("mpls_ttl".to_string(), Value::Array(mpls_ttl));
        
        let mpls_label: Vec<Value> = record.mpls_label.iter().map(|&x| Value::Number(serde_json::Number::from(x))).collect();
        map.insert("mpls_label".to_string(), Value::Array(mpls_label));
        
        map.insert("observation_domain_id".to_string(), Value::Number(serde_json::Number::from(record.observation_domain_id)));
        map.insert("observation_point_id".to_string(), Value::Number(serde_json::Number::from(record.observation_point_id)));
        
        let layer_stack: Vec<Value> = record.layer_stack.iter().map(|l| Value::String(self.layer_stack_to_string(l).to_string())).collect();
        map.insert("layer_stack".to_string(), Value::Array(layer_stack));
        
        let layer_size: Vec<Value> = record.layer_size.iter().map(|&x| Value::Number(serde_json::Number::from(x))).collect();
        map.insert("layer_size".to_string(), Value::Array(layer_size));
        
        let ipv6_routing_header_addresses: Vec<Value> = record.ipv6_routing_header_addresses.iter().map(|addr| Value::String(self.format_address(addr))).collect();
        map.insert("ipv6_routing_header_addresses".to_string(), Value::Array(ipv6_routing_header_addresses));
        
        map.insert("ipv6_routing_header_seg_left".to_string(), Value::Number(serde_json::Number::from(record.ipv6_routing_header_seg_left)));
        
        // Add enterprise fields
        if !record.enterprise_fields.is_empty() {
            let mut enterprise_map = serde_json::Map::new();
            for ((pen, field_type), data) in &record.enterprise_fields {
                let key = format!("enterprise_{}_{}", pen, field_type);
                enterprise_map.insert(key, Value::String(hex::encode(data)));
            }
            map.insert("enterprise_fields".to_string(), Value::Object(enterprise_map));
        }

        // Add metadata if requested
        if self.include_metadata {
            map.insert("sampler_address".to_string(), Value::String(self.format_address(&record.sampler_address)));
        }

        Value::Object(map)
    }
}

impl Formatter for JsonFormatter {
    fn format(&self, record: &FlowRecord) -> Result<Vec<u8>> {
        let json = self.record_to_json(record);
        Ok(serde_json::to_vec(&json)?)
    }

    fn format_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>> {
        let json_array: Vec<Value> = records.iter().map(|r| self.record_to_json(r)).collect();
        Ok(serde_json::to_vec(&json_array)?)
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
} 

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoders::{FlowRecord, FlowType};

    #[test]
    fn test_json_formatter_basic() {
        let formatter = JsonFormatter::new();
        let mut record = FlowRecord::default();
        record.src_as = 0x0100007f; // 127.0.0.1
        record.dst_as = 0x0100007f; // 127.0.0.1
        record.src_port = 8080;
        record.dst_port = 80;
        record.flow_type = FlowType::SFlow5;

        let result = formatter.format(&record).unwrap();
        let json_str = String::from_utf8(result).unwrap();
        
        // Basic validation that JSON was generated
        assert!(!json_str.is_empty());
        assert!(json_str.starts_with('{'));
        assert!(json_str.ends_with('}'));
    }

    #[test]
    fn test_json_formatter_with_metadata() {
        let formatter = JsonFormatter::new()._with_metadata(true);
        let record = FlowRecord::default();

        let result = formatter.format(&record).unwrap();
        let json_str = String::from_utf8(result).unwrap();
        
        // Should include metadata fields
        assert!(json_str.contains("\"sampler_address\""));
    }

    #[test]
    fn test_json_formatter_without_metadata() {
        let formatter = JsonFormatter::new()._with_metadata(false);
        let record = FlowRecord::default();

        let result = formatter.format(&record).unwrap();
        let json_str = String::from_utf8(result).unwrap();
        
        // Should not include metadata fields
        assert!(!json_str.contains("\"sampler_address\""));
    }
} 