use crate::config::MappingConfig;
use crate::decoders::FlowRecord;
use crate::producer::Producer;
use anyhow::Result;
use prost::Message;
use std::collections::HashMap;

// Include the generated protobuf code
pub mod flowpb {
    include!(concat!(env!("OUT_DIR"), "/flowpb.rs"));
}

use flowpb::flow_message::{FlowType as ProtoFlowType, LayerStack as ProtoLayerStack};

pub struct ProtoProducer {
    _config: MappingConfig,
    _field_mappings: HashMap<u16, String>,
}

impl ProtoProducer {
    pub fn new(config: MappingConfig) -> Self {
        let mut field_mappings = HashMap::new();
        
        if let Some(ref ipfix_mapping) = config.ipfix {
            for mapping in &ipfix_mapping.mapping {
                field_mappings.insert(mapping.field, mapping.destination.clone());
            }
        }
        
        Self {
            _config: config,
            _field_mappings: field_mappings,
        }
    }

    fn flow_type_to_proto(&self, flow_type: &crate::decoders::FlowType) -> i32 {
        match flow_type {
            crate::decoders::FlowType::SFlow5 => ProtoFlowType::Sflow5 as i32,
            crate::decoders::FlowType::NetFlowV5 => ProtoFlowType::NetflowV5 as i32,
            crate::decoders::FlowType::NetFlowV9 => ProtoFlowType::NetflowV9 as i32,
            crate::decoders::FlowType::IPFIX => ProtoFlowType::Ipfix as i32,
        }
    }

    fn string_to_layer_stack(&self, layer: &str) -> i32 {
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
        
        // Set current timestamp if not provided
        let time_received = if record.time_received_ns == 0 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        } else {
            record.time_received_ns
        };
        
        proto.r#type = self.flow_type_to_proto(&record.flow_type);
        proto.time_received_ns = time_received;
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
        proto.layer_stack = record.layer_stack.iter().map(|l| self.string_to_layer_stack(l)).collect();
        proto.layer_size = record.layer_size.clone();
        proto.ipv6_routing_header_addresses = record.ipv6_routing_header_addresses.clone();
        proto.ipv6_routing_header_seg_left = record.ipv6_routing_header_seg_left;

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

impl Producer for ProtoProducer {
    fn produce(&self, record: &FlowRecord) -> Result<Vec<u8>> {
        let proto = self.record_to_proto(record);
        let bytes = proto.encode_to_vec();
        
        // Add length prefix
        let length_bytes = self.write_varint(bytes.len() as u64);
        let mut result = Vec::with_capacity(length_bytes.len() + bytes.len());
        result.extend_from_slice(&length_bytes);
        result.extend_from_slice(&bytes);
        
        Ok(result)
    }

    fn produce_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        for record in records {
            let bytes = self.produce(record)?;
            result.extend_from_slice(&bytes);
        }
        
        Ok(result)
    }
} 