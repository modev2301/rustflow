use crate::decoders::{Decoder, FlowRecord, FlowType};
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::fmt;
use tracing::{debug, error, warn};

// Error types matching Go implementation
#[derive(Debug)]
pub struct DecoderError {
    pub decoder: String,
    pub error: anyhow::Error,
}

impl fmt::Display for DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.decoder, self.error)
    }
}

impl std::error::Error for DecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

#[derive(Debug)]
pub struct FlowError {
    pub version: u16,
    pub flow_type: String,
    pub obs_domain_id: u32,
    pub template_id: u16,
    pub error: anyhow::Error,
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[version:{} type:{} obsDomainId:{} templateId:{}] {}",
            self.version, self.flow_type, self.obs_domain_id, self.template_id, self.error
        )
    }
}

impl std::error::Error for FlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

// Template management system
pub trait NetFlowTemplateSystem {
    fn add_template(&mut self, version: u16, obs_domain_id: u32, template_id: u16, template: TemplateType) -> Result<()>;
    fn get_template(&self, version: u16, obs_domain_id: u32, template_id: u16) -> Result<&TemplateType>;
}

#[derive(Debug, Clone)]
pub enum TemplateType {
    Regular(TemplateRecord),
    NetFlowV9Options(NFv9OptionsTemplateRecord),
    IPFIXOptions(IPFIXOptionsTemplateRecord),
}

#[derive(Debug, Clone)]
pub struct DefaultTemplateSystem {
    templates: HashMap<(u16, u32, u16), TemplateType>, // (version, obs_domain_id, template_id)
}

impl DefaultTemplateSystem {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }
}

impl NetFlowTemplateSystem for DefaultTemplateSystem {
    fn add_template(&mut self, version: u16, obs_domain_id: u32, template_id: u16, template: TemplateType) -> Result<()> {
        self.templates.insert((version, obs_domain_id, template_id), template);
        Ok(())
    }

    fn get_template(&self, version: u16, obs_domain_id: u32, template_id: u16) -> Result<&TemplateType> {
        self.templates
            .get(&(version, obs_domain_id, template_id))
            .ok_or_else(|| anyhow!("Template not found"))
    }
}

// Data structures matching Go implementation
#[derive(Debug, Clone)]
pub struct Field {
    pub field_type: u16,
    pub length: u16,
    pub pen_provided: bool,
    pub pen: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NFv9OptionsTemplateRecord {
    pub template_id: u16,
    pub scope_length: u16,
    pub option_length: u16,
    pub scopes: Vec<Field>,
    pub options: Vec<Field>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IPFIXOptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub scopes: Vec<Field>,
    pub options: Vec<Field>,
}

#[derive(Debug, Clone)]
pub struct FlowSetHeader {
    pub id: u16,
    pub length: u16,
}

#[derive(Debug, Clone)]
pub struct DataField {
    pub field_type: u16,
    pub pen_provided: bool,
    pub pen: u32,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DataRecord {
    pub values: Vec<DataField>,
}

#[derive(Debug, Clone)]
pub struct OptionsDataRecord {
    pub scopes_values: Vec<DataField>,
    pub options_values: Vec<DataField>,
}

// FlowSet types
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum FlowSet {
    Template(TemplateFlowSet),
    NFv9OptionsTemplate(NFv9OptionsTemplateFlowSet),
    IPFIXOptionsTemplate(IPFIXOptionsTemplateFlowSet),
    Data(DataFlowSet),
    OptionsData(OptionsDataFlowSet),
    Raw(RawFlowSet),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TemplateFlowSet {
    pub header: FlowSetHeader,
    pub records: Vec<TemplateRecord>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NFv9OptionsTemplateFlowSet {
    pub header: FlowSetHeader,
    pub records: Vec<NFv9OptionsTemplateRecord>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IPFIXOptionsTemplateFlowSet {
    pub header: FlowSetHeader,
    pub records: Vec<IPFIXOptionsTemplateRecord>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DataFlowSet {
    pub header: FlowSetHeader,
    pub records: Vec<DataRecord>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OptionsDataFlowSet {
    pub header: FlowSetHeader,
    pub records: Vec<OptionsDataRecord>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawFlowSet {
    pub header: FlowSetHeader,
    pub records: Vec<u8>,
}

// Packet structures
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NFv9Packet {
    pub version: u16,
    pub count: u16,
    pub system_uptime: u32,
    pub unix_seconds: u32,
    pub sequence_number: u32,
    pub source_id: u32,
    pub flow_sets: Vec<FlowSet>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IPFIXPacket {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    pub flow_sets: Vec<FlowSet>,
}

#[derive(Debug, Clone)]
pub struct NetFlowDecoder {
    templates: DefaultTemplateSystem,
}

impl NetFlowDecoder {
    pub fn new() -> Self {
        Self {
            templates: DefaultTemplateSystem::new(),
        }
    }

    #[allow(dead_code)]
    pub async fn start_collector(addr: &str) -> Result<()> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let mut decoder = NetFlowDecoder::new();
        let mut buf = vec![0u8; 9000];

        tracing::info!("NetFlow collector listening on {}", addr);

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    debug!("Received {} bytes from {}", len, src);
                    
                    if let Err(e) = decoder.process_packet(data).await {
                        error!("Error processing packet: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                }
            }
        }
    }

    #[allow(dead_code)]
    async fn process_packet(&mut self, data: Bytes) -> Result<Vec<FlowRecord>> {
        self.decode_message_version(data)
    }

    fn decode_message_version(&mut self, mut data: Bytes) -> Result<Vec<FlowRecord>> {
        if data.len() < 2 {
            return Err(anyhow!("Packet too short for version"));
        }

        let version = data.get_u16();
        debug!("Processing NetFlow packet version {}", version);

        match version {
            5 => self.decode_netflow_v5(data),
            9 => {
                let mut packet = NFv9Packet {
                    version: 9,
                    count: 0,
                    system_uptime: 0,
                    unix_seconds: 0,
                    sequence_number: 0,
                    source_id: 0,
                    flow_sets: Vec::new(),
                };
                self.decode_message_netflow(&mut data, &mut packet)?;
                self.convert_packet_to_flow_records(&packet)
            }
            10 => {
                let mut packet = IPFIXPacket {
                    version: 10,
                    length: 0,
                    export_time: 0,
                    sequence_number: 0,
                    observation_domain_id: 0,
                    flow_sets: Vec::new(),
                };
                self.decode_message_ipfix(&mut data, &mut packet)?;
                self.convert_packet_to_flow_records_ipfix(&packet)
            }
            _ => {
                warn!("Unsupported NetFlow version: {}", version);
                Ok(Vec::new())
            }
        }
    }

    fn decode_netflow_v5(&self, mut data: Bytes) -> Result<Vec<FlowRecord>> {
        if data.len() < 22 { // 24 total - 2 already read for version
            return Err(anyhow!("NetFlow v5 packet too short"));
        }

        // Read header
        let count = data.get_u16();
        let _system_uptime = data.get_u32();
        let _unix_seconds = data.get_u32();
        let _unix_nsecs = data.get_u32();
        let _flow_sequence = data.get_u32();
        let _engine_type = data.get_u8();
        let _engine_id = data.get_u8();
        let _sampling_interval = data.get_u16();

        let mut records = Vec::new();
        for _ in 0..count {
            if data.len() < 48 {
                break;
            }
            records.push(self.decode_netflow_v5_record(&mut data)?);
        }

        debug!("Decoded {} NetFlow v5 records", records.len());
        Ok(records)
    }

    fn decode_netflow_v5_record(&self, data: &mut Bytes) -> Result<FlowRecord> {
        let mut record = FlowRecord::default();
        record.flow_type = FlowType::NetFlowV5;

        record.src_addr = data.copy_to_bytes(4).to_vec();
        record.dst_addr = data.copy_to_bytes(4).to_vec();
        record.next_hop = data.copy_to_bytes(4).to_vec();
        record.in_if = data.get_u16() as u32;
        record.out_if = data.get_u16() as u32;
        record.packets = data.get_u32() as u64;
        record.bytes = data.get_u32() as u64;
        record.time_flow_start_ns = data.get_u32() as u64 * 1_000_000_000;
        record.time_flow_end_ns = data.get_u32() as u64 * 1_000_000_000;
        record.src_port = data.get_u16() as u32;
        record.dst_port = data.get_u16() as u32;
        let _pad1 = data.get_u8();
        record.tcp_flags = data.get_u8() as u32;
        record.proto = data.get_u8() as u32;
        record.ip_tos = data.get_u8() as u32;
        record.src_as = data.get_u16() as u32;
        record.dst_as = data.get_u16() as u32;
        let _src_mask = data.get_u8();
        let _dst_mask = data.get_u8();
        let _pad2 = data.get_u16();

        Ok(record)
    }

    fn decode_message_netflow(&mut self, data: &mut Bytes, packet: &mut NFv9Packet) -> Result<()> {
        if data.len() < 18 { // 20 total - 2 already read for version
            return Err(anyhow!("NetFlow v9 header too short"));
        }

        packet.count = data.get_u16();
        packet.system_uptime = data.get_u32();
        packet.unix_seconds = data.get_u32();
        packet.sequence_number = data.get_u32();
        packet.source_id = data.get_u32();

        let flow_sets = self.decode_message_common(
            data,
            packet.source_id,
            packet.count,
            9,
        )?;
        packet.flow_sets = flow_sets;

        Ok(())
    }

    fn decode_message_ipfix(&mut self, data: &mut Bytes, packet: &mut IPFIXPacket) -> Result<()> {
        if data.len() < 14 { // 16 total - 2 already read for version
            return Err(anyhow!("IPFIX header too short"));
        }

        packet.length = data.get_u16();
        packet.export_time = data.get_u32();
        packet.sequence_number = data.get_u32();
        packet.observation_domain_id = data.get_u32();

        let flow_sets = self.decode_message_common(
            data,
            packet.observation_domain_id,
            packet.length - 16,
            10,
        )?;
        packet.flow_sets = flow_sets;

        Ok(())
    }

    fn decode_message_common(
        &mut self,
        data: &mut Bytes,
        obs_domain_id: u32,
        size: u16,
        version: u16,
    ) -> Result<Vec<FlowSet>> {
        let mut flow_sets = Vec::new();
        let mut read = 0u16;
        let start_size = data.len();

        while ((version == 9 && flow_sets.len() < size as usize) || 
               (version == 10 && read < size)) && 
              data.len() > 0 {
            
            match self.decode_message_common_flow_set(data, obs_domain_id, version) {
                Ok(flow_set) => flow_sets.push(flow_set),
                Err(e) => {
                    error!("Error decoding flow set: {}", e);
                    break;
                }
            }
            
            read = (start_size - data.len()) as u16;
        }

        Ok(flow_sets)
    }

    fn decode_message_common_flow_set(
        &mut self,
        data: &mut Bytes,
        obs_domain_id: u32,
        version: u16,
    ) -> Result<FlowSet> {
        if data.len() < 4 {
            return Err(anyhow!("FlowSet header too short"));
        }

        let header = FlowSetHeader {
            id: data.get_u16(),
            length: data.get_u16(),
        };

        let next_rel_pos = header.length as usize - 4;
        if next_rel_pos > data.len() {
            return Err(anyhow!("FlowSet length exceeds available data"));
        }

        let set_data = data.copy_to_bytes(next_rel_pos);

        match (header.id, version) {
            (0, 9) => {
                // NFv9 Template Set
                let records = self.decode_template_set(&set_data, version)?;
                for record in &records {
                    self.templates.add_template(
                        version,
                        obs_domain_id,
                        record.template_id,
                        TemplateType::Regular(record.clone()),
                    )?;
                }
                Ok(FlowSet::Template(TemplateFlowSet { header, records }))
            }
            (1, 9) => {
                // NFv9 Options Template Set
                let records = self.decode_nfv9_options_template_set(&set_data)?;
                for record in &records {
                    self.templates.add_template(
                        version,
                        obs_domain_id,
                        record.template_id,
                        TemplateType::NetFlowV9Options(record.clone()),
                    )?;
                }
                Ok(FlowSet::NFv9OptionsTemplate(NFv9OptionsTemplateFlowSet { header, records }))
            }
            (2, 10) => {
                // IPFIX Template Set
                let records = self.decode_template_set(&set_data, version)?;
                for record in &records {
                    self.templates.add_template(
                        version,
                        obs_domain_id,
                        record.template_id,
                        TemplateType::Regular(record.clone()),
                    )?;
                }
                Ok(FlowSet::Template(TemplateFlowSet { header, records }))
            }
            (3, 10) => {
                // IPFIX Options Template Set
                let records = self.decode_ipfix_options_template_set(&set_data)?;
                for record in &records {
                    self.templates.add_template(
                        version,
                        obs_domain_id,
                        record.template_id,
                        TemplateType::IPFIXOptions(record.clone()),
                    )?;
                }
                Ok(FlowSet::IPFIXOptionsTemplate(IPFIXOptionsTemplateFlowSet { header, records }))
            }
            (id, _) if id >= 256 => {
                // Data Set
                let raw_flow_set = RawFlowSet {
                    header: header.clone(),
                    records: set_data.to_vec(),
                };

                match self.templates.get_template(version, obs_domain_id, header.id) {
                    Ok(template) => match template {
                        TemplateType::Regular(template_record) => {
                            let records = self.decode_data_set(&set_data, version, &template_record.fields)?;
                            Ok(FlowSet::Data(DataFlowSet { header, records }))
                        }
                        TemplateType::NetFlowV9Options(opts_template) => {
                            let records = self.decode_options_data_set(
                                &set_data,
                                version,
                                &opts_template.scopes,
                                &opts_template.options,
                            )?;
                            Ok(FlowSet::OptionsData(OptionsDataFlowSet { header, records }))
                        }
                        TemplateType::IPFIXOptions(opts_template) => {
                            let records = self.decode_options_data_set(
                                &set_data,
                                version,
                                &opts_template.scopes,
                                &opts_template.options,
                            )?;
                            Ok(FlowSet::OptionsData(OptionsDataFlowSet { header, records }))
                        }
                    },
                    Err(_) => {
                        debug!("Template not found for ID {}, returning raw", header.id);
                        Ok(FlowSet::Raw(raw_flow_set))
                    }
                }
            }
            _ => Err(anyhow!("Unknown FlowSet ID: {}", header.id)),
        }
    }

    fn decode_field(&self, data: &mut Bytes, pen: bool) -> Result<Field> {
        if data.len() < 4 {
            return Err(anyhow!("Insufficient data for field"));
        }

        let field_type = data.get_u16();
        let length = data.get_u16();

        let mut field = Field {
            field_type,
            length,
            pen_provided: false,
            pen: 0,
        };

        if pen && field_type & 0x8000 != 0 {
            if data.len() < 4 {
                return Err(anyhow!("Insufficient data for PEN"));
            }
            field.pen_provided = true;
            field.pen = data.get_u32();
            field.field_type = field_type & 0x7FFF;
        }

        Ok(field)
    }

    fn decode_template_set(&self, data: &Bytes, version: u16) -> Result<Vec<TemplateRecord>> {
        let mut data = data.clone();
        let mut records = Vec::new();

        while data.len() >= 4 {
            let template_id = data.get_u16();
            let field_count = data.get_u16();

            if field_count == 0 {
                return Err(anyhow!("Template field count is zero"));
            }

            let mut fields = Vec::new();
            for _ in 0..field_count {
                let field = self.decode_field(&mut data, version == 10)?;
                fields.push(field);
            }

            records.push(TemplateRecord {
                template_id,
                field_count,
                fields,
            });
        }

        Ok(records)
    }

    fn decode_nfv9_options_template_set(&self, data: &Bytes) -> Result<Vec<NFv9OptionsTemplateRecord>> {
        let mut data = data.clone();
        let mut records = Vec::new();

        while data.len() >= 6 {
            let template_id = data.get_u16();
            let scope_length = data.get_u16();
            let option_length = data.get_u16();

            let scope_size = scope_length as usize / 4;
            let option_size = option_length as usize / 4;

            if scope_size == 0 && option_size == 0 {
                return Err(anyhow!("NFv9OptionsTemplateSet: negative length"));
            }

            let mut scopes = Vec::new();
            for _ in 0..scope_size {
                let field = self.decode_field(&mut data, false)?;
                scopes.push(field);
            }

            let mut options = Vec::new();
            for _ in 0..option_size {
                let field = self.decode_field(&mut data, false)?;
                options.push(field);
            }

            records.push(NFv9OptionsTemplateRecord {
                template_id,
                scope_length,
                option_length,
                scopes,
                options,
            });
        }

        Ok(records)
    }

    fn decode_ipfix_options_template_set(&self, data: &Bytes) -> Result<Vec<IPFIXOptionsTemplateRecord>> {
        let mut data = data.clone();
        let mut records = Vec::new();

        while data.len() >= 6 {
            let template_id = data.get_u16();
            let field_count = data.get_u16();
            let scope_field_count = data.get_u16();

            let mut scopes = Vec::new();
            for _ in 0..scope_field_count {
                let field = self.decode_field(&mut data, true)?;
                scopes.push(field);
            }

            let options_size = field_count - scope_field_count;
            if options_size == 0 {
                return Err(anyhow!("IPFIXOptionsTemplateSet: negative length"));
            }

            let mut options = Vec::new();
            for _ in 0..options_size {
                let field = self.decode_field(&mut data, true)?;
                options.push(field);
            }

            records.push(IPFIXOptionsTemplateRecord {
                template_id,
                field_count,
                scope_field_count,
                scopes,
                options,
            });
        }

        Ok(records)
    }

    fn get_template_size(&self, template: &[Field]) -> usize {
        template
            .iter()
            .map(|field| {
                if field.length == 0xffff {
                    0 // Variable length, skip in size calculation
                } else {
                    field.length as usize
                }
            })
            .sum()
    }

    fn decode_data_set_using_fields(
        &self,
        data: &mut Bytes,
        fields: &[Field],
        _version: u16,
    ) -> Result<Vec<DataField>> {
        let mut data_fields = Vec::new();
        let template_size = self.get_template_size(fields);

        if data.len() < template_size {
            return Err(anyhow!("Insufficient data for template"));
        }

        for field in fields {
            let final_length = if field.length == 0xffff {
                // Variable length field
                if data.len() < 1 {
                    return Err(anyhow!("Insufficient data for variable length"));
                }
                let variable_len8 = data.get_u8();
                if variable_len8 == 0xff {
                    if data.len() < 2 {
                        return Err(anyhow!("Insufficient data for variable length"));
                    }
                    data.get_u16() as usize
                } else {
                    variable_len8 as usize
                }
            } else {
                field.length as usize
            };

            if data.len() < final_length {
                return Err(anyhow!("Insufficient data for field"));
            }

            let value = data.copy_to_bytes(final_length).to_vec();
            data_fields.push(DataField {
                field_type: field.field_type,
                pen_provided: field.pen_provided,
                pen: field.pen,
                value,
            });
        }

        Ok(data_fields)
    }

    fn decode_data_set(&self, data: &Bytes, version: u16, fields: &[Field]) -> Result<Vec<DataRecord>> {
        let mut data = data.clone();
        let mut records = Vec::new();
        let template_size = self.get_template_size(fields);

        while data.len() >= template_size {
            let values = self.decode_data_set_using_fields(&mut data, fields, version)?;
            records.push(DataRecord { values });
        }

        Ok(records)
    }

    fn decode_options_data_set(
        &self,
        data: &Bytes,
        version: u16,
        scope_fields: &[Field],
        option_fields: &[Field],
    ) -> Result<Vec<OptionsDataRecord>> {
        let mut data = data.clone();
        let mut records = Vec::new();
        let scope_size = self.get_template_size(scope_fields);
        let option_size = self.get_template_size(option_fields);

        while data.len() >= scope_size + option_size {
            let scopes_values = self.decode_data_set_using_fields(&mut data, scope_fields, version)?;
            let options_values = self.decode_data_set_using_fields(&mut data, option_fields, version)?;
            
            records.push(OptionsDataRecord {
                scopes_values,
                options_values,
            });
        }

        Ok(records)
    }

    fn convert_packet_to_flow_records(&self, packet: &NFv9Packet) -> Result<Vec<FlowRecord>> {
        let mut records = Vec::new();

        for flow_set in &packet.flow_sets {
            match flow_set {
                FlowSet::Data(data_flow_set) => {
                    for data_record in &data_flow_set.records {
                        let mut record = FlowRecord::default();
                        record.flow_type = FlowType::NetFlowV9;
                        
                        for data_field in &data_record.values {
                            self.map_field_to_record(&mut record, data_field)?;
                        }
                        
                        records.push(record);
                    }
                }
                FlowSet::OptionsData(options_flow_set) => {
                    for options_record in &options_flow_set.records {
                        let mut record = FlowRecord::default();
                        record.flow_type = FlowType::NetFlowV9;
                        
                        // Map scope fields
                        for data_field in &options_record.scopes_values {
                            self.map_field_to_record(&mut record, data_field)?;
                        }
                        
                        // Map option fields
                        for data_field in &options_record.options_values {
                            self.map_field_to_record(&mut record, data_field)?;
                        }
                        
                        records.push(record);
                    }
                }
                _ => {} // Skip template sets and raw sets
            }
        }

        Ok(records)
    }

    fn map_field_to_record(&self, record: &mut FlowRecord, data_field: &DataField) -> Result<()> {
        if data_field.pen_provided {
            // Handle enterprise fields
            record.enterprise_fields.insert(
                (data_field.pen, data_field.field_type),
                data_field.value.clone(),
            );
            
            match data_field.pen {
                9 => self.handle_cisco_enterprise_fields(record, data_field.field_type, &data_field.value)?,
                23867 => self.handle_silverpeak_enterprise_fields(record, data_field.field_type, &data_field.value)?,
                _ => {
                    debug!("Unknown enterprise: PEN={}, field_type={}", data_field.pen, data_field.field_type);
                }
            }
        } else {
            // Handle standard IANA fields
            match data_field.field_type {
                1 => record.in_if = self.read_u32_from_bytes(&data_field.value)?,
                2 => record.out_if = self.read_u32_from_bytes(&data_field.value)?,
                4 => record.proto = self.read_u8_from_bytes(&data_field.value)? as u32,
                5 => record.ip_tos = self.read_u8_from_bytes(&data_field.value)? as u32,
                6 => record.tcp_flags = self.read_u8_from_bytes(&data_field.value)? as u32,
                7 => record.src_port = self.read_u16_from_bytes(&data_field.value)? as u32,
                8 => record.dst_port = self.read_u16_from_bytes(&data_field.value)? as u32,
                9 => record.ip_ttl = self.read_u8_from_bytes(&data_field.value)? as u32,
                10 => record.ip_flags = self.read_u8_from_bytes(&data_field.value)? as u32,
                11 => record.src_as = self.read_u16_from_bytes(&data_field.value)? as u32,
                12 => record.dst_as = self.read_u16_from_bytes(&data_field.value)? as u32,
                13 => record.src_addr = data_field.value.clone(), // IPv4 source
                14 => record.dst_addr = data_field.value.clone(), // IPv4 destination
                15 => record.next_hop = data_field.value.clone(),
                16 => record.src_as = self.read_u16_from_bytes(&data_field.value)? as u32,
                17 => record.dst_as = self.read_u16_from_bytes(&data_field.value)? as u32,
                18 => record.src_mask = self.read_u8_from_bytes(&data_field.value)? as u32,
                19 => record.dst_mask = self.read_u8_from_bytes(&data_field.value)? as u32,
                21 => record.time_flow_start_ns = self.read_u32_from_bytes(&data_field.value)? as u64 * 1_000_000_000,
                22 => record.time_flow_end_ns = self.read_u32_from_bytes(&data_field.value)? as u64 * 1_000_000_000,
                23 => record.packets = self.read_u32_from_bytes(&data_field.value)? as u64,
                24 => record.bytes = self.read_u32_from_bytes(&data_field.value)? as u64,
                27 => record.src_addr = data_field.value.clone(), // IPv6 source
                28 => record.dst_addr = data_field.value.clone(), // IPv6 destination
                32 => record.icmp_type = self.read_u16_from_bytes(&data_field.value)? as u32,
                56 => record.src_mac = self.read_u64_from_bytes(&data_field.value)?,
                57 => record.dst_mac = self.read_u64_from_bytes(&data_field.value)?,
                58 => record.src_vlan = self.read_u16_from_bytes(&data_field.value)? as u32,
                59 => record.dst_vlan = self.read_u16_from_bytes(&data_field.value)? as u32,
                60 => record.ip_version = self.read_u8_from_bytes(&data_field.value)? as u32,
                61 => record.direction = self.read_u8_from_bytes(&data_field.value)? as u32,
                62 => record.next_hop = data_field.value.clone(), // IPv6 next hop
                70 => record.mpls_label_1 = self.read_u32_from_bytes(&data_field.value)?,
                71 => record.mpls_label_2 = self.read_u32_from_bytes(&data_field.value)?,
                72 => record.mpls_label_3 = self.read_u32_from_bytes(&data_field.value)?,
                73 => record.mpls_label_4 = self.read_u32_from_bytes(&data_field.value)?,
                74 => record.mpls_label_5 = self.read_u32_from_bytes(&data_field.value)?,
                75 => record.mpls_label_6 = self.read_u32_from_bytes(&data_field.value)?,
                76 => record.mpls_label_7 = self.read_u32_from_bytes(&data_field.value)?,
                77 => record.mpls_label_8 = self.read_u32_from_bytes(&data_field.value)?,
                78 => record.mpls_label_9 = self.read_u32_from_bytes(&data_field.value)?,
                79 => record.mpls_label_10 = self.read_u32_from_bytes(&data_field.value)?,
                80 => record.src_mac = self.read_u64_from_bytes(&data_field.value)?, // in_src_mac
                81 => record.dst_mac = self.read_u64_from_bytes(&data_field.value)?, // out_dst_mac
                130 => record.exporter_addr = data_field.value.clone(),
                131 => record.exporter_addr = data_field.value.clone(), // IPv6 exporter
                136 => record.flow_label = self.read_u32_from_bytes(&data_field.value)?,
                148 => record.flow_id = self.read_u64_from_bytes(&data_field.value)?,
                150 => record.time_flow_start_ns = self.read_u64_from_bytes(&data_field.value)? * 1_000_000, // seconds to ns
                151 => record.time_flow_end_ns = self.read_u64_from_bytes(&data_field.value)? * 1_000_000, // seconds to ns
                152 => record.time_flow_start_ns = self.read_u64_from_bytes(&data_field.value)? * 1_000, // milliseconds to ns
                153 => record.time_flow_end_ns = self.read_u64_from_bytes(&data_field.value)? * 1_000, // milliseconds to ns
                154 => record.time_flow_start_ns = self.read_u64_from_bytes(&data_field.value)? * 1_000_000_000, // microseconds to ns
                155 => record.time_flow_end_ns = self.read_u64_from_bytes(&data_field.value)? * 1_000_000_000, // microseconds to ns
                156 => record.time_flow_start_ns = self.read_u64_from_bytes(&data_field.value)?, // nanoseconds
                157 => record.time_flow_end_ns = self.read_u64_from_bytes(&data_field.value)?, // nanoseconds
                176 => record.icmp_type = self.read_u8_from_bytes(&data_field.value)? as u32,
                177 => record.icmp_code = self.read_u8_from_bytes(&data_field.value)? as u32,
                178 => record.icmp_type = self.read_u8_from_bytes(&data_field.value)? as u32, // ICMPv6 type
                179 => record.icmp_code = self.read_u8_from_bytes(&data_field.value)? as u32, // ICMPv6 code
                _ => {
                    debug!("Unknown field type: {}", data_field.field_type);
                }
            }
        }

        Ok(())
    }

    fn read_u8_from_bytes(&self, data: &[u8]) -> Result<u8> {
        if data.is_empty() {
            return Err(anyhow!("Insufficient data for u8"));
        }
        Ok(data[0])
    }

    fn read_u16_from_bytes(&self, data: &[u8]) -> Result<u16> {
        if data.len() < 2 {
            return Err(anyhow!("Insufficient data for u16"));
        }
        Ok(u16::from_be_bytes([data[0], data[1]]))
    }

    fn read_u32_from_bytes(&self, data: &[u8]) -> Result<u32> {
        match data.len() {
            1 => Ok(data[0] as u32),
            2 => Ok(u16::from_be_bytes([data[0], data[1]]) as u32),
            4 => Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
            _ => Err(anyhow!("Invalid data length for u32: {}", data.len())),
        }
    }

    fn read_u64_from_bytes(&self, data: &[u8]) -> Result<u64> {
        match data.len() {
            1 => Ok(data[0] as u64),
            2 => Ok(u16::from_be_bytes([data[0], data[1]]) as u64),
            4 => Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64),
            6 => {
                // MAC address
                let mut bytes = [0u8; 8];
                bytes[2..8].copy_from_slice(data);
                Ok(u64::from_be_bytes(bytes))
            }
            8 => Ok(u64::from_be_bytes([
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7],
            ])),
            _ => Err(anyhow!("Invalid data length for u64: {}", data.len())),
        }
    }

    fn handle_cisco_enterprise_fields(&self, record: &mut FlowRecord, field_type: u16, data: &[u8]) -> Result<()> {
        match field_type {
            1..=20 => {
                // Cisco MPLS labels 1-10 (in/out pairs)
                if data.len() >= 4 {
                    let label = self.read_u32_from_bytes(data)?;
                    match field_type {
                        1 | 2 => record.mpls_label_1 = label,
                        3 | 4 => record.mpls_label_2 = label,
                        5 | 6 => record.mpls_label_3 = label,
                        7 | 8 => record.mpls_label_4 = label,
                        9 | 10 => record.mpls_label_5 = label,
                        11 | 12 => record.mpls_label_6 = label,
                        13 | 14 => record.mpls_label_7 = label,
                        15 | 16 => record.mpls_label_8 = label,
                        17 | 18 => record.mpls_label_9 = label,
                        19 | 20 => record.mpls_label_10 = label,
                        _ => {}
                    }
                }
            }
            21 => {
                // Engine type
                if !data.is_empty() {
                    record.engine_type = data[0] as u32;
                }
            }
            22 => {
                // Engine ID
                if !data.is_empty() {
                    record.engine_id = data[0] as u32;
                }
            }
            23 => {
                // VRF name
                record.vrf_name = String::from_utf8_lossy(data).to_string();
            }
            24 => {
                // Application ID
                if data.len() >= 4 {
                    record.application_id = self.read_u32_from_bytes(data)?;
                }
            }
            _ => {
                debug!("Unknown Cisco enterprise field: {}", field_type);
            }
        }
        Ok(())
    }

    fn handle_silverpeak_enterprise_fields(&self, record: &mut FlowRecord, field_type: u16, data: &[u8]) -> Result<()> {
        match field_type {
            1 => {
                // WAN Optimization Application ID
                if data.len() >= 4 {
                    let app_id = self.read_u32_from_bytes(data)?;
                    record.wan_opt_app_id = app_id;
                    debug!("Silver Peak WAN Optimization App ID: {}", app_id);
                }
            }
            2 => {
                // WAN Optimization Connection ID
                if data.len() >= 8 {
                    let conn_id = self.read_u64_from_bytes(data)?;
                    record.wan_opt_conn_id = conn_id;
                    debug!("Silver Peak WAN Optimization Connection ID: {}", conn_id);
                }
            }
            3 => {
                // WAN Optimization Bytes Original
                if data.len() >= 8 {
                    let bytes_orig = self.read_u64_from_bytes(data)?;
                    record.wan_opt_bytes_orig = bytes_orig;
                    debug!("Silver Peak WAN Optimization Original Bytes: {}", bytes_orig);
                }
            }
            4 => {
                // WAN Optimization Bytes Optimized
                if data.len() >= 8 {
                    let bytes_opt = self.read_u64_from_bytes(data)?;
                    record.wan_opt_bytes_opt = bytes_opt;
                    debug!("Silver Peak WAN Optimization Optimized Bytes: {}", bytes_opt);
                }
            }
            5 => {
                // WAN Optimization Packets Original
                if data.len() >= 8 {
                    let packets_orig = self.read_u64_from_bytes(data)?;
                    record.wan_opt_packets_orig = packets_orig;
                    debug!("Silver Peak WAN Optimization Original Packets: {}", packets_orig);
                }
            }
            6 => {
                // WAN Optimization Packets Optimized
                if data.len() >= 8 {
                    let packets_opt = self.read_u64_from_bytes(data)?;
                    record.wan_opt_packets_opt = packets_opt;
                    debug!("Silver Peak WAN Optimization Optimized Packets: {}", packets_opt);
                }
            }
            7 => {
                // WAN Optimization Compression Ratio
                if data.len() >= 4 {
                    let ratio = self.read_u32_from_bytes(data)?;
                    record.wan_opt_compression_ratio = ratio;
                    debug!("Silver Peak WAN Optimization Compression Ratio: {}", ratio);
                }
            }
            8 => {
                // WAN Optimization Latency MS
                if data.len() >= 4 {
                    let latency = self.read_u32_from_bytes(data)?;
                    record.wan_opt_latency_ms = latency;
                    debug!("Silver Peak WAN Optimization Latency: {}ms", latency);
                }
            }
            9 => {
                // WAN Optimization Jitter MS
                if data.len() >= 4 {
                    let jitter = self.read_u32_from_bytes(data)?;
                    record.wan_opt_jitter_ms = jitter;
                    debug!("Silver Peak WAN Optimization Jitter: {}ms", jitter);
                }
            }
            10 => {
                // WAN Optimization Packet Loss Percent
                if data.len() >= 4 {
                    let loss = self.read_u32_from_bytes(data)?;
                    record.wan_opt_packet_loss_percent = loss;
                    debug!("Silver Peak WAN Optimization Packet Loss: {}%", loss);
                }
            }
            _ => {
                debug!("Unknown Silver Peak enterprise field: {}", field_type);
            }
        }
        Ok(())
    }
}

impl Decoder for NetFlowDecoder {
    fn decode(&self, data: Bytes) -> Result<Vec<FlowRecord>> {
        // Since decode_message_version needs &mut self, we need to create a new instance
        // This is a limitation of the trait design - in practice, we'd want to use a different approach
        let mut decoder = self.clone();
        decoder.decode_message_version(data)
    }
}

// Additional utility functions for compatibility
#[allow(dead_code)]
impl NetFlowDecoder {
    pub fn decode_with_templates(&mut self, data: Bytes) -> Result<Vec<FlowRecord>> {
        self.decode_message_version(data)
    }

    pub fn get_template_count(&self) -> usize {
        self.templates.templates.len()
    }

    pub fn clear_templates(&mut self) {
        self.templates.templates.clear();
    }

    pub fn add_external_template(&mut self, version: u16, obs_domain_id: u32, template_id: u16, template: TemplateType) -> Result<()> {
        self.templates.add_template(version, obs_domain_id, template_id, template)
    }

    // Create template from field definitions
    pub fn create_template_record(template_id: u16, fields: Vec<(u16, u16, Option<u32>)>) -> TemplateRecord {
        let mut template_fields = Vec::new();
        
        for (field_type, length, pen) in fields {
            template_fields.push(Field {
                field_type,
                length,
                pen_provided: pen.is_some(),
                pen: pen.unwrap_or(0),
            });
        }

        TemplateRecord {
            template_id,
            field_count: template_fields.len() as u16,
            fields: template_fields,
        }
    }

    // Create options template from field definitions
    pub fn create_nfv9_options_template_record(
        template_id: u16,
        scope_fields: Vec<(u16, u16)>,
        option_fields: Vec<(u16, u16)>,
    ) -> NFv9OptionsTemplateRecord {
        let mut scopes = Vec::new();
        let mut options = Vec::new();

        for (field_type, length) in scope_fields {
            scopes.push(Field {
                field_type,
                length,
                pen_provided: false,
                pen: 0,
            });
        }

        for (field_type, length) in option_fields {
            options.push(Field {
                field_type,
                length,
                pen_provided: false,
                pen: 0,
            });
        }

        NFv9OptionsTemplateRecord {
            template_id,
            scope_length: (scopes.len() * 4) as u16,
            option_length: (options.len() * 4) as u16,
            scopes,
            options,
        }
    }

    pub fn create_ipfix_options_template_record(
        template_id: u16,
        scope_fields: Vec<(u16, u16, Option<u32>)>,
        option_fields: Vec<(u16, u16, Option<u32>)>,
    ) -> IPFIXOptionsTemplateRecord {
        let mut scopes = Vec::new();
        let mut options = Vec::new();

        for (field_type, length, pen) in scope_fields {
            scopes.push(Field {
                field_type,
                length,
                pen_provided: pen.is_some(),
                pen: pen.unwrap_or(0),
            });
        }

        for (field_type, length, pen) in option_fields {
            options.push(Field {
                field_type,
                length,
                pen_provided: pen.is_some(),
                pen: pen.unwrap_or(0),
            });
        }

        IPFIXOptionsTemplateRecord {
            template_id,
            field_count: (scopes.len() + options.len()) as u16,
            scope_field_count: scopes.len() as u16,
            scopes,
            options,
        }
    }

    fn convert_packet_to_flow_records_ipfix(&self, packet: &IPFIXPacket) -> Result<Vec<FlowRecord>> {
        let mut records = Vec::new();

        for flow_set in &packet.flow_sets {
            match flow_set {
                FlowSet::Data(data_flow_set) => {
                    for data_record in &data_flow_set.records {
                        let mut record = FlowRecord::default();
                        record.flow_type = FlowType::IPFIX;
                        
                        for data_field in &data_record.values {
                            self.map_field_to_record(&mut record, data_field)?;
                        }
                        
                        records.push(record);
                    }
                }
                FlowSet::OptionsData(options_flow_set) => {
                    for options_record in &options_flow_set.records {
                        let mut record = FlowRecord::default();
                        record.flow_type = FlowType::IPFIX;
                        
                        // Map scope fields
                        for data_field in &options_record.scopes_values {
                            self.map_field_to_record(&mut record, data_field)?;
                        }
                        
                        // Map option fields
                        for data_field in &options_record.options_values {
                            self.map_field_to_record(&mut record, data_field)?;
                        }
                        
                        records.push(record);
                    }
                }
                _ => {} // Skip template sets and raw sets
            }
        }

        Ok(records)
    }
}