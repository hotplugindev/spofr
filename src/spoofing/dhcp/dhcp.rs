use dialoguer::{theme::ColorfulTheme, Input, Select};
use pnet::datalink::{self, NetworkInterface, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub interface: Option<NetworkInterface>,
    pub start_ip: Option<Ipv4Addr>,
    pub end_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
    pub _lease_time: u32,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            interface: None,
            start_ip: None,
            end_ip: None,
            subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            router: None,
            dns: Some(Ipv4Addr::new(8, 8, 8, 8)),
            _lease_time: 86400,
        }
    }
}

pub fn run() {
    let mut config = DhcpConfig::default();
    let selections = &["List network settings", "Set network settings", "Start", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("DHCP Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "List network settings" => list_network_settings(),
            "Set network settings" => set_network_settings(&mut config),
            "Start" => start_dhcp(&config),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn list_network_settings() {
    // Reuse similar logic from ARP, or just call a shared function if we refactored.
    // For now, duplicate for independence.
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

fn set_network_settings(config: &mut DhcpConfig) {
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

    // Auto-suggest based on interface IP
    let mut suggested_router = Ipv4Addr::new(192, 168, 1, 1);
    let mut suggested_start = Ipv4Addr::new(192, 168, 1, 100);
    let mut suggested_end = Ipv4Addr::new(192, 168, 1, 200);

    if let Some(ip_net) = selected_interface.ips.iter().find(|ip| ip.is_ipv4()) {
        if let std::net::IpAddr::V4(ipv4) = ip_net.ip() {
            // Assume router is .1
            let octets = ipv4.octets();
            suggested_router = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
            suggested_start = Ipv4Addr::new(octets[0], octets[1], octets[2], 100);
            suggested_end = Ipv4Addr::new(octets[0], octets[1], octets[2], 200);
        }
    }

    let router_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Router (Gateway) IP")
        .default(suggested_router.to_string())
        .interact_text()
        .unwrap();
    config.router = Some(Ipv4Addr::from_str(&router_input).unwrap_or(suggested_router));

    let start_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Pool Start IP")
        .default(suggested_start.to_string())
        .interact_text()
        .unwrap();
    config.start_ip = Some(Ipv4Addr::from_str(&start_input).unwrap_or(suggested_start));

    let end_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Pool End IP")
        .default(suggested_end.to_string())
        .interact_text()
        .unwrap();
    config.end_ip = Some(Ipv4Addr::from_str(&end_input).unwrap_or(suggested_end));

    let dns_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("DNS Server")
        .default("8.8.8.8".to_string())
        .interact_text()
        .unwrap();
    config.dns = Some(Ipv4Addr::from_str(&dns_input).unwrap_or(Ipv4Addr::new(8, 8, 8, 8)));

    println!("DHCP Configuration Updated.");
}

fn start_dhcp(config: &DhcpConfig) {
    if config.interface.is_none() || config.start_ip.is_none() || config.end_ip.is_none() || config.router.is_none() {
        println!("Error: Missing configuration.");
        return;
    }

    let interface = config.interface.as_ref().unwrap();
    let server_ip = config.router.unwrap(); // Acting as the router/server
    let _start_ip = config.start_ip.unwrap();
    let _end_ip = config.end_ip.unwrap();
    let dns_ip = config.dns.unwrap();
    let subnet_mask = config.subnet_mask.unwrap();

    println!("Starting DHCP Server on {}...", interface.name);
    println!("Pool: {} - {}", _start_ip, _end_ip);
    println!("Router: {}", server_ip);
    println!("DNS: {}", dns_ip);
    println!("Press Ctrl+C to stop.");

    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
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

    let _running = Arc::new(AtomicBool::new(true));
    
    // Simple loop to listen for DHCP Discover and respond
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4 = Ipv4Packet::new(ethernet.payload()).unwrap();
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        let udp = UdpPacket::new(ipv4.payload()).unwrap();
                        // DHCP Server listens on 67, Client sends to 67
                        if udp.get_destination() == 67 {
                            handle_dhcp_packet(packet, &mut *tx, interface, server_ip, dns_ip, subnet_mask, _start_ip);
                        }
                    }
                }
            },
            Err(_) => continue,
        }
    }
}

fn handle_dhcp_packet(
    packet: &[u8], 
    tx: &mut dyn datalink::DataLinkSender, 
    interface: &NetworkInterface,
    server_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    offer_ip: Ipv4Addr // Simplification: Always offer start_ip
) {
    let ethernet = EthernetPacket::new(packet).unwrap();
    let ipv4 = Ipv4Packet::new(ethernet.payload()).unwrap();
    let udp = UdpPacket::new(ipv4.payload()).unwrap();
    let payload = udp.payload();

    // Basic DHCP parsing (Magic Cookie check)
    if payload.len() < 240 { return; }
    if payload[236] != 0x63 || payload[237] != 0x82 || payload[238] != 0x53 || payload[239] != 0x63 {
        return; // Invalid Magic Cookie
    }

    let _op = payload[0];
    let xid = &payload[4..8];
    let chaddr = &payload[28..44]; // Client HW Addr
    let client_mac = MacAddr::new(chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);

    // Parse Options to find Message Type
    let mut msg_type = 0;
    let mut i = 240;
    while i < payload.len() {
        let code = payload[i];
        if code == 255 { break; } // End
        if code == 0 { i += 1; continue; } // Pad
        let len = payload[i+1] as usize;
        if code == 53 && len == 1 {
            msg_type = payload[i+2];
        }
        i += 2 + len;
    }

    if msg_type == 1 { // DHCP Discover
        println!("Received DHCP Discover from {}", client_mac);
        send_dhcp_reply(tx, interface, client_mac, xid, offer_ip, server_ip, dns_ip, subnet_mask, 2); // Offer
    } else if msg_type == 3 { // DHCP Request
        println!("Received DHCP Request from {}", client_mac);
        send_dhcp_reply(tx, interface, client_mac, xid, offer_ip, server_ip, dns_ip, subnet_mask, 5); // Ack
    }
}

fn send_dhcp_reply(
    tx: &mut dyn datalink::DataLinkSender,
    interface: &NetworkInterface,
    target_mac: MacAddr,
    xid: &[u8],
    yiaddr: Ipv4Addr, // Your (Client) IP
    server_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    msg_type: u8 // 2 = Offer, 5 = Ack
) {
    let mut ethernet_buffer = [0u8; 342]; // 14 Eth + 20 IP + 8 UDP + 300 DHCP
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(328); // 20 + 8 + 300
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(server_ip);
    ipv4_packet.set_destination(yiaddr); // Unicast to offered IP (or broadcast if client can't receive)
    // Actually, for Offer/Ack before config, usually broadcast 255.255.255.255 or unicast to MAC if supported.
    // Let's use broadcast for simplicity in initial handshake or yiaddr if we are confident.
    // Standard often says broadcast if GIADDR is 0.
    ipv4_packet.set_destination(Ipv4Addr::new(255, 255, 255, 255));
    ipv4_packet.set_destination(yiaddr); // Try unicast first? No, client doesn't have IP yet.
    // Revert to broadcast for safety in this simple implementation
    ipv4_packet.set_destination(Ipv4Addr::new(255, 255, 255, 255));
    ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));

    let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
    udp_packet.set_source(67);
    udp_packet.set_destination(68);
    udp_packet.set_length(308); // 8 + 300
    
    // Construct DHCP Payload
    let payload = udp_packet.payload_mut();
    // Clear
    for b in payload.iter_mut() { *b = 0; }

    payload[0] = 2; // Boot Reply
    payload[1] = 1; // Ethernet
    payload[2] = 6; // HW Len
    payload[3] = 0; // Hops
    
    // XID
    payload[4] = xid[0];
    payload[5] = xid[1];
    payload[6] = xid[2];
    payload[7] = xid[3];

    // YIADDR (Your IP)
    let yi_octets = yiaddr.octets();
    payload[16] = yi_octets[0];
    payload[17] = yi_octets[1];
    payload[18] = yi_octets[2];
    payload[19] = yi_octets[3];

    // SIADDR (Server IP)
    let si_octets = server_ip.octets();
    payload[20] = si_octets[0];
    payload[21] = si_octets[1];
    payload[22] = si_octets[2];
    payload[23] = si_octets[3];

    // CHADDR (Client HW Addr)
    let mac_octets = target_mac.octets();
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

    // Option 53: Message Type
    payload[cursor] = 53;
    payload[cursor+1] = 1;
    payload[cursor+2] = msg_type;
    cursor += 3;

    // Option 1: Subnet Mask
    let mask_octets = subnet_mask.octets();
    payload[cursor] = 1;
    payload[cursor+1] = 4;
    payload[cursor+2] = mask_octets[0];
    payload[cursor+3] = mask_octets[1];
    payload[cursor+4] = mask_octets[2];
    payload[cursor+5] = mask_octets[3];
    cursor += 6;

    // Option 3: Router
    payload[cursor] = 3;
    payload[cursor+1] = 4;
    payload[cursor+2] = si_octets[0];
    payload[cursor+3] = si_octets[1];
    payload[cursor+4] = si_octets[2];
    payload[cursor+5] = si_octets[3];
    cursor += 6;

    // Option 6: DNS
    let dns_octets = dns_ip.octets();
    payload[cursor] = 6;
    payload[cursor+1] = 4;
    payload[cursor+2] = dns_octets[0];
    payload[cursor+3] = dns_octets[1];
    payload[cursor+4] = dns_octets[2];
    payload[cursor+5] = dns_octets[3];
    cursor += 6;

    // Option 54: Server Identifier
    payload[cursor] = 54;
    payload[cursor+1] = 4;
    payload[cursor+2] = si_octets[0];
    payload[cursor+3] = si_octets[1];
    payload[cursor+4] = si_octets[2];
    payload[cursor+5] = si_octets[3];
    cursor += 6;

    // Option 51: Lease Time (86400s)
    payload[cursor] = 51;
    payload[cursor+1] = 4;
    payload[cursor+2] = 0;
    payload[cursor+3] = 1;
    payload[cursor+4] = 0x51;
    payload[cursor+5] = 0x80;
    cursor += 6;

    // End Option
    payload[cursor] = 255;

    // UDP Checksum
    udp_packet.set_checksum(ipv4_checksum(&udp_packet.to_immutable(), &server_ip, &Ipv4Addr::new(255, 255, 255, 255)));

    tx.send_to(ethernet_packet.packet(), None);
    
    if msg_type == 2 {
        println!("Sent DHCP Offer to {} with IP {}", target_mac, yiaddr);
    } else {
        println!("Sent DHCP Ack to {} with IP {}", target_mac, yiaddr);
    }
}
