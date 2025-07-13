use anyhow::Result;
use bytes::{Buf, Bytes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub trait BinaryDecoder {
    fn _read_u8(&mut self) -> Result<u8>;
    fn _read_u16(&mut self) -> Result<u16>;
    fn _read_u32(&mut self) -> Result<u32>;
    fn _read_u64(&mut self) -> Result<u64>;
    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>>;
    fn read_ipv4(&mut self) -> Result<Ipv4Addr>;
    fn read_ipv6(&mut self) -> Result<Ipv6Addr>;
    fn _read_ip(&mut self) -> Result<IpAddr>;
}

impl BinaryDecoder for Bytes {
    fn _read_u8(&mut self) -> Result<u8> {
        if self.len() < 1 {
            return Err(anyhow::anyhow!("Not enough data for u8"));
        }
        Ok(self.get_u8())
    }

    fn _read_u16(&mut self) -> Result<u16> {
        if self.len() < 2 {
            return Err(anyhow::anyhow!("Not enough data for u16"));
        }
        Ok(self.get_u16())
    }

    fn _read_u32(&mut self) -> Result<u32> {
        if self.len() < 4 {
            return Err(anyhow::anyhow!("Not enough data for u32"));
        }
        Ok(self.get_u32())
    }

    fn _read_u64(&mut self) -> Result<u64> {
        if self.len() < 8 {
            return Err(anyhow::anyhow!("Not enough data for u64"));
        }
        Ok(self.get_u64())
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.len() < len {
            return Err(anyhow::anyhow!("Not enough data for {} bytes", len));
        }
        Ok(self.copy_to_bytes(len).to_vec())
    }

    fn read_ipv4(&mut self) -> Result<Ipv4Addr> {
        let bytes = self.read_bytes(4)?;
        Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }

    fn read_ipv6(&mut self) -> Result<Ipv6Addr> {
        let bytes = self.read_bytes(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes);
        Ok(Ipv6Addr::from(octets))
    }

    fn _read_ip(&mut self) -> Result<IpAddr> {
        // Try IPv4 first, then IPv6
        if self.len() >= 4 {
            let bytes = &self[..4];
            if bytes.iter().any(|&b| b != 0) {
                return Ok(IpAddr::V4(self.read_ipv4()?));
            }
        }
        
        if self.len() >= 16 {
            return Ok(IpAddr::V6(self.read_ipv6()?));
        }
        
        Err(anyhow::anyhow!("Could not determine IP address type"))
    }
}

pub fn bytes_to_ipv4(bytes: &[u8]) -> Result<Ipv4Addr> {
    if bytes.len() != 4 {
        return Err(anyhow::anyhow!("Invalid IPv4 address length"));
    }
    Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

pub fn bytes_to_ipv6(bytes: &[u8]) -> Result<Ipv6Addr> {
    if bytes.len() != 16 {
        return Err(anyhow::anyhow!("Invalid IPv6 address length"));
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    Ok(Ipv6Addr::from(octets))
}

pub fn _bytes_to_mac(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address length"));
    }
    
    let mut mac = 0u64;
    for (i, &byte) in bytes.iter().enumerate() {
        mac |= (byte as u64) << ((5 - i) * 8);
    }
    Ok(mac)
}

pub fn mac_to_bytes(mac: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6);
    for i in 0..6 {
        bytes.push(((mac >> ((5 - i) * 8)) & 0xFF) as u8);
    }
    bytes
}

pub fn _ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
        IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
    }
}

pub fn _format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => {
            if let Ok(ip) = bytes_to_ipv4(bytes) {
                ip.to_string()
            } else {
                format!("{:?}", bytes)
            }
        }
        16 => {
            if let Ok(ip) = bytes_to_ipv6(bytes) {
                ip.to_string()
            } else {
                format!("{:?}", bytes)
            }
        }
        _ => format!("{:?}", bytes),
    }
}

pub fn format_mac(mac: u64) -> String {
    let bytes = mac_to_bytes(mac);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
} 

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_bytes_to_mac() {
        let mac_bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = _bytes_to_mac(&mac_bytes).unwrap();
        assert_eq!(result, 0x001122334455);
    }

    #[test]
    fn test_bytes_to_mac_invalid_length() {
        let mac_bytes = [0x00, 0x11, 0x22, 0x33, 0x44]; // 5 bytes instead of 6
        let result = _bytes_to_mac(&mac_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_to_bytes_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let bytes = _ip_to_bytes(ip);
        assert_eq!(bytes, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_ip_to_bytes_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let bytes = _ip_to_bytes(ip);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_format_ip_ipv4() {
        let ip_bytes = [192, 168, 1, 1];
        let result = _format_ip(&ip_bytes);
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_format_ip_ipv6() {
        let ip_bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        ];
        let result = _format_ip(&ip_bytes);
        assert_eq!(result, "2001:db8::1");
    }

    #[test]
    fn test_is_valid_port() {
        assert!(crate::utils::_is_valid_port(1));
        assert!(crate::utils::_is_valid_port(1024));
        assert!(crate::utils::_is_valid_port(65534));
        assert!(!crate::utils::_is_valid_port(0));
        assert!(!crate::utils::_is_valid_port(65535));
    }

    #[test]
    fn test_validate_ipv4() {
        assert!(crate::utils::_validate_ipv4("192.168.1.1"));
        assert!(crate::utils::_validate_ipv4("127.0.0.1"));
        assert!(!crate::utils::_validate_ipv4("256.1.2.3"));
        assert!(!crate::utils::_validate_ipv4("192.168.1"));
        assert!(!crate::utils::_validate_ipv4("192.168.1.1.1"));
    }

    #[test]
    fn test_validate_ipv6() {
        assert!(crate::utils::_validate_ipv6("2001:db8::1"));
        assert!(crate::utils::_validate_ipv6("::1"));
        assert!(crate::utils::_validate_ipv6("fe80::1"));
        assert!(!crate::utils::_validate_ipv6("2001:db8::1::"));
        assert!(!crate::utils::_validate_ipv6("2001:db8::1:"));
    }

    #[test]
    fn test_validate_ip() {
        assert!(crate::utils::_validate_ip("192.168.1.1"));
        assert!(crate::utils::_validate_ip("2001:db8::1"));
        assert!(!crate::utils::_validate_ip("invalid"));
        assert!(!crate::utils::_validate_ip("192.168.1"));
    }

    #[test]
    fn test_parse_address() {
        let result = crate::utils::_parse_address("192.168.1.1:8080").unwrap();
        assert_eq!(result.0, "192.168.1.1");
        assert_eq!(result.1, 8080);

        let result = crate::utils::_parse_address("[2001:db8::1]:8080").unwrap();
        assert_eq!(result.0, "2001:db8::1");
        assert_eq!(result.1, 8080);
    }

    #[test]
    fn test_parse_address_invalid() {
        assert!(crate::utils::_parse_address("invalid").is_err());
        assert!(crate::utils::_parse_address("192.168.1.1").is_err());
        assert!(crate::utils::_parse_address("192.168.1.1:99999").is_err());
    }
} 