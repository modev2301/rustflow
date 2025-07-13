use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod netflow;
pub mod sflow;
pub mod utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowType {
    NetFlowV5,
    NetFlowV9,
    IPFIX,
    SFlow5,
}

impl Default for FlowType {
    fn default() -> Self {
        FlowType::NetFlowV5
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayerStack {
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    MPLS,
    Dot1Q,
    ICMP,
    ICMPv6,
    GRE,
    IPv6HeaderRouting,
    IPv6HeaderFragment,
    Geneve,
    Teredo,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowRecord {
    pub flow_type: FlowType,
    pub sequence_num: u32,
    pub sampling_rate: u64,
    pub sampler_address: Vec<u8>,
    pub in_if: u32,
    pub out_if: u32,
    pub src_addr: Vec<u8>,
    pub dst_addr: Vec<u8>,
    pub next_hop: Vec<u8>,
    pub src_port: u32,
    pub dst_port: u32,
    pub proto: u32,
    pub tcp_flags: u32,
    pub ip_tos: u32,
    pub ip_ttl: u32,
    pub ip_flags: u32,
    pub src_as: u32,
    pub dst_as: u32,
    pub src_mac: u64,
    pub dst_mac: u64,
    pub src_vlan: u32,
    pub dst_vlan: u32,
    pub etype: u32,
    pub packets: u64,
    pub bytes: u64,
    pub time_flow_start_ns: u64,
    pub time_flow_end_ns: u64,
    // Additional fields for extended flow information
    pub time_received_ns: u64,
    pub vlan_id: u32,
    pub forwarding_status: u32,
    pub icmp_type: u32,
    pub icmp_code: u32,
    pub ipv6_flow_label: u32,
    pub fragment_id: u32,
    pub fragment_offset: u32,
    pub next_hop_as: u32,
    pub src_net: u32,
    pub dst_net: u32,
    pub bgp_next_hop: Vec<u8>,
    pub bgp_communities: Vec<u32>,
    pub as_path: Vec<u32>,
    pub mpls_ttl: Vec<u32>,
    pub mpls_label: Vec<u32>,
    pub mpls_ip: Vec<Vec<u8>>,
    pub observation_domain_id: u32,
    pub observation_point_id: u32,
    pub layer_stack: Vec<String>,
    pub layer_size: Vec<u32>,
    pub ipv6_routing_header_addresses: Vec<Vec<u8>>,
    pub ipv6_routing_header_seg_left: u32,
    // Enterprise fields support
    pub enterprise_fields: HashMap<(u32, u16), Vec<u8>>, // (PEN, field_type) -> data
    
    // Additional fields for NetFlow v9/IPFIX support
    pub src_mask: u32,
    pub dst_mask: u32,
    pub ip_version: u32,
    pub direction: u32,
    pub exporter_addr: Vec<u8>,
    pub flow_label: u32,
    pub flow_id: u64,
    pub engine_type: u32,
    pub engine_id: u32,
    pub vrf_name: String,
    pub application_id: u32,
    
    // MPLS label fields (individual labels for enterprise support)
    pub mpls_label_1: u32,
    pub mpls_label_2: u32,
    pub mpls_label_3: u32,
    pub mpls_label_4: u32,
    pub mpls_label_5: u32,
    pub mpls_label_6: u32,
    pub mpls_label_7: u32,
    pub mpls_label_8: u32,
    pub mpls_label_9: u32,
    pub mpls_label_10: u32,
    
    // Silver Peak WAN Optimization fields
    pub wan_opt_app_id: u32,
    pub wan_opt_conn_id: u64,
    pub wan_opt_bytes_orig: u64,
    pub wan_opt_bytes_opt: u64,
    pub wan_opt_packets_orig: u64,
    pub wan_opt_packets_opt: u64,
    pub wan_opt_compression_ratio: u32,
    pub wan_opt_latency_ms: u32,
    pub wan_opt_jitter_ms: u32,
    pub wan_opt_packet_loss_percent: u32,
}

pub trait Decoder: Send + Sync {
    fn decode(&self, data: Bytes) -> Result<Vec<FlowRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_flow_record_default() {
        let record = FlowRecord::default();
        assert_eq!(record.sequence_num, 0);
        assert_eq!(record.sampling_rate, 0);
        assert_eq!(record.in_if, 0);
        assert_eq!(record.out_if, 0);
        assert_eq!(record.src_port, 0);
        assert_eq!(record.dst_port, 0);
        assert_eq!(record.proto, 0);
        assert_eq!(record.packets, 0);
        assert_eq!(record.bytes, 0);
    }

    #[test]
    fn test_flow_record_serialization() {
        let mut record = FlowRecord::default();
        record.flow_type = FlowType::NetFlowV5;
        record.src_addr = vec![192, 168, 1, 1];
        record.dst_addr = vec![192, 168, 1, 2];
        record.src_port = 80;
        record.dst_port = 443;
        record.proto = 6; // TCP

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: FlowRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.src_port, 80);
        assert_eq!(deserialized.dst_port, 443);
        assert_eq!(deserialized.proto, 6);
    }

    #[test]
    fn test_decoder_trait() {
        struct MockDecoder;
        
        impl Decoder for MockDecoder {
            fn decode(&self, _data: Bytes) -> Result<Vec<FlowRecord>> {
                Ok(vec![FlowRecord::default()])
            }
        }

        let decoder = MockDecoder;
        let data = Bytes::from(vec![0, 1, 2, 3]);
        let result = decoder.decode(data).unwrap();
        assert_eq!(result.len(), 1);
    }
} 