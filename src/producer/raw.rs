use crate::decoders::FlowRecord;
use crate::producer::Producer;
use anyhow::Result;
use serde_json;

pub struct RawProducer {
    _include_metadata: bool,
}

impl RawProducer {
    pub fn new() -> Self {
        Self {
            _include_metadata: false,
        }
    }

    pub fn _with_metadata(mut self, include: bool) -> Self {
        self._include_metadata = include;
        self
    }
}

impl Producer for RawProducer {
    fn produce(&self, record: &FlowRecord) -> Result<Vec<u8>> {
        // Convert to JSON for raw output
        let json = serde_json::to_vec(&record)?;
        Ok(json)
    }

    fn produce_batch(&self, records: &[FlowRecord]) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(&records)?;
        Ok(json)
    }
}

impl Default for RawProducer {
    fn default() -> Self {
        Self::new()
    }
} 