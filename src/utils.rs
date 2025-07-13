use anyhow::Result;

pub fn _get_current_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub fn _format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.1} {}", size, UNITS[unit_index])
}

pub fn _format_duration_ns(nanos: u64) -> String {
    let seconds = nanos / 1_000_000_000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;
    
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours % 24, minutes % 60, seconds % 60)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes % 60, seconds % 60)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds % 60)
    } else {
        format!("{}s", seconds)
    }
}

pub fn _parse_address(addr: &str) -> Result<(String, u16)> {
    // Handle IPv6 addresses with brackets: [2001:db8::1]:8080
    if addr.starts_with('[') && addr.contains("]:") {
        let end_bracket = addr.find(']').ok_or_else(|| {
            anyhow::anyhow!("Invalid IPv6 address format: {}", addr)
        })?;
        
        let host = addr[1..end_bracket].to_string();
        let port_str = &addr[end_bracket + 2..]; // Skip "]:"
        let port = port_str.parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port number: {}", port_str))?;
        
        Ok((host, port))
    } else {
        // Handle regular IPv4 addresses: 192.168.1.1:8080
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid address format: {}", addr));
        }
        
        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port number: {}", parts[1]))?;
        
        Ok((host, port))
    }
}

pub fn _is_valid_port(port: u16) -> bool {
    port > 0 && port < 65535
}

pub fn _validate_ipv4(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

pub fn _validate_ipv6(ip: &str) -> bool {
    ip.parse::<std::net::Ipv6Addr>().is_ok()
}

pub fn _validate_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}