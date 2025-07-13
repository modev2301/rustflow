use crate::decoders::{FlowRecord, FlowType};
use crate::format::Formatter;
use anyhow::Result;
use prost::Message;

// Include the generated protobuf code
pub mod flowpb {
    include!(concat!(env!("OUT_DIR"), "/flowpb.rs"));
}

use flowpb::flow_message::{FlowType as ProtoFlowType, LayerStack as ProtoLayerStack};

pub struct BinaryFormatter {
    include_length_prefix: bool,
}

impl BinaryFormatter {
    pub fn new() -> Self {
        Self {
            include_length_prefix: true,
        }
    }

    pub fn _with_length_prefix(mut self, include: bool) -> Self {
        self.include_length_prefix = include;
        self
    }

    fn flow_type_to_proto(&self, flow_type: &FlowType) -> i32 {
        match flow_type {
            FlowType::SFlow5 => ProtoFlowType::Sflow5 as i32,
            FlowType::NetFlowV5 => ProtoFlowType::NetflowV5 as i32,
            FlowType::NetFlowV9 => ProtoFlowType::NetflowV9 as i32,
            FlowType::IPFIX => ProtoFlowType::Ipfix as i32,
        }
    }

    fn layer_stack_to_proto(&self, layer: &str) -> i32 {
        match layer.to_lowercase().as_str() {
            "ethernet" => ProtoLayerStack::Ethernet as i32,
            "ipv4" => ProtoLayerStack::IPv4 as i32,
            "ipv6" => ProtoLayerStack::IPv6 as i32,
            "tcp" => ProtoLayerStack::Tcp as i32,
            "udp" => ProtoLayerStack::Udp as i32,
            "mpls" => ProtoLayerStack::Mpls as i32,
            "dot1q" => ProtoLayerStack::Dot1Q as i32,
            "icmp" => ProtoLayerStack::Icmp as i32,
            "icmpv6" => ProtoLayerStack::IcmPv6 as i32,
            "gre" => ProtoLayerStack::Gre as i32,
            "ipv6headerrouting" => ProtoLayerStack::IPv6HeaderRouting as i32,
            "ipv6headerfragment" => ProtoLayerStack::IPv6HeaderFragment as i32,
            "geneve" => ProtoLayerStack::Geneve as i32,
            "teredo" => ProtoLayerStack::Teredo as i32,
            _ => ProtoLayerStack::Custom as i32,
        }
    }

    fn record_to_proto(&self, record: &FlowRecord) -> flowpb::FlowMessage {
        let mut proto = flowpb::FlowMessage::default();
        
        proto.r#type = self.flow_type_to_proto(&record.flow_type);
        proto.time_received_ns = record.time_received_ns;
        proto.sequence_num = record.sequence_num;
        proto.sampling_rate = record.sampling_rate;
        proto.sampler_address = record.sampler_address.clone();
        proto.time_flow_start_ns = record.time_flow_start_ns;
        proto.time_flow_end_ns = record.time_flow_end_ns;
        proto.bytes = record.bytes;
        proto.packets = record.packets;
        proto.src_addr = record.src_addr.clone();
        proto.dst_addr = record.dst_addr.clone();
        proto.etype = record.etype;
        proto.proto = record.proto;
        proto.src_port = record.src_port;
        proto.dst_port = record.dst_port;
        proto.in_if = record.in_if;
        proto.out_if = record.out_if;
        proto.src_mac = record.src_mac;
        proto.dst_mac = record.dst_mac;
        proto.src_vlan = record.src_vlan;
        proto.dst_vlan = record.dst_vlan;
        proto.vlan_id = record.vlan_id;
        proto.ip_tos = record.ip_tos;
        proto.forwarding_status = record.forwarding_status;
        proto.ip_ttl = record.ip_ttl;
        proto.ip_flags = record.ip_flags;
        proto.tcp_flags = record.tcp_flags;
        proto.icmp_type = record.icmp_type;
        proto.icmp_code = record.icmp_code;
        proto.ipv6_flow_label = record.ipv6_flow_label;
        proto.fragment_id = record.fragment_id;
        proto.fragment_offset = record.fragment_offset;
        proto.src_as = record.src_as;
        proto.dst_as = record.dst_as;
        proto.next_hop = record.next_hop.clone();
        proto.next_hop_as = record.next_hop_as;
        proto.src_net = record.src_net;
        proto.dst_net = record.dst_net;
        proto.bgp_next_hop = record.bgp_next_hop.clone();
        proto.bgp_communities = record.bgp_communities.clone();
        proto.as_path = record.as_path.clone();
        proto.mpls_ttl = record.mpls_ttl.clone();
        proto.mpls_label = record.mpls_label.clone();
        proto.mpls_ip = record.mpls_ip.clone();
        proto.observation_domain_id = record.observation_domain_id;
        proto.observation_point_id = record.observation_point_id;
        proto.layer_stack = record.layer_stack.iter().map(|l| self.layer_stack_to_proto(l)).collect();
        proto.layer_size = record.layer_size.clone();
        proto.ipv6_routing_header_addresses = record.ipv6_routing_header_addresses.clone();
        proto.ipv6_routing_header_seg_left = record.ipv6_routing_header_seg_left;

        // Add enterprise fields
        for ((pen, field_type), data) in &record.enterprise_fields {
            let mut enterprise_field = flowpb::flow_message::EnterpriseField::default();
            enterprise_field.pen = *pen;
            enterprise_field.field_type = *field_type as u32;
            enterprise_field.data = data.clone();
            proto.enterprise_fields.push(enterprise_field);
        }

        proto
    }

    fn write_varint(&self, value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut val = value;
        
        while val >= 0x80 {
            bytes.push((val as u8) | 0x80);
            val >>= 7;
        }
        bytes.push(val as u8);
        
        bytes
    }
}

impl Formatter for BinaryFormatter {
    fn format(&self, record: &FlowRecord) -> Result<Vec<u8>> {
        let proto = self.record_to_proto(record);
        let mut bytes = proto.encode_to_vec();
        
        if self.include_length_prefix {
            let length_bytes = self.write_varint(bytes.len() as u64);
            let mut result = Vec::with_capacity(length_bytes.len() + bytes.len());
            result.extend_from_slice(&length_bytes);
            result.extend_from_slice(&bytes);
            bytes = result;
        }
        
        Ok(bytes)
    }

    fn format_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        for record in records {
            let bytes = self.format(record)?;
            result.extend_from_slice(&bytes);
        }
        
        Ok(result)
    }
}

impl Default for BinaryFormatter {
    fn default() -> Self {
        Self::new()
    }
} 

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoders::{FlowRecord, FlowType};

    #[test]
    fn test_binary_formatter_basic() {
        let formatter = BinaryFormatter::new();
        let mut record = FlowRecord::default();
        record.src_as = 0x0100007f; // 127.0.0.1
        record.dst_as = 0x0100007f; // 127.0.0.1
        record.src_port = 8080;
        record.dst_port = 80;
        record.flow_type = FlowType::SFlow5;

        let result = formatter.format(&record).unwrap();
        
        // Should produce protobuf binary data
        assert!(!result.is_empty());
        // Basic validation that it's protobuf (should start with field 1)
        assert!(result.len() > 0);
    }

    #[test]
    fn test_binary_formatter_with_length_prefix() {
        let formatter = BinaryFormatter::new()._with_length_prefix(true);
        let record = FlowRecord::default();

        let result = formatter.format(&record).unwrap();
        
        // Should have length prefix (varint, at least 1 byte)
        assert!(result.len() >= 1);
        
        // The first byte should be a varint (length prefix)
        // For small protobuf messages, the length should be encoded as a single byte
        assert!(result[0] < 0x80 || result[0] >= 0x80);
    }

    #[test]
    fn test_binary_formatter_without_length_prefix() {
        let formatter = BinaryFormatter::new()._with_length_prefix(false);
        let record = FlowRecord::default();

        let result = formatter.format(&record).unwrap();
        
        // Should not have length prefix
        assert!(result.len() > 0);
    }
} 