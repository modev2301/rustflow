use crate::transport::Transporter;
use anyhow::Result;
use std::io::{self, Write};
use tracing::info;

pub struct FileTransporter {
    file_path: Option<String>,
    append: bool,
    separator: String,
}

impl FileTransporter {
    pub fn new() -> Self {
        Self {
            file_path: None,
            append: true,
            separator: "\n".to_string(),
        }
    }

    pub fn _with_file(mut self, path: String) -> Self {
        self.file_path = Some(path);
        self
    }

    pub fn _with_append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    pub fn _with_separator(mut self, separator: String) -> Self {
        self.separator = separator;
        self
    }

    async fn _write_to_file(&self, data: &[u8]) -> Result<()> {
        // Implementation would write data to file
        // For now, just log the data length
        info!("Would write {} bytes to file", data.len());
        Ok(())
    }
}

impl Transporter for FileTransporter {
    fn send(&self, data: &[u8]) -> Result<()> {
        // For now, we'll use blocking I/O for simplicity
        // In a real implementation, you'd want to use async I/O
        if let Some(ref path) = self.file_path {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(self.append)
                .open(path)?;
            
            file.write_all(data)?;
            file.write_all(self.separator.as_bytes())?;
            file.flush()?;
        } else {
            // Write to stdout
            let mut stdout = io::stdout();
            stdout.write_all(data)?;
            stdout.write_all(self.separator.as_bytes())?;
            stdout.flush()?;
        }
        
        Ok(())
    }

    fn send_batch(&self, data: &[Vec<u8>]) -> Result<()> {
        for item in data {
            self.send(item)?;
        }
        Ok(())
    }
}

impl Default for FileTransporter {
    fn default() -> Self {
        Self::new()
    }
} 