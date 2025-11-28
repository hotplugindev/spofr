use dialoguer::{theme::ColorfulTheme, Select};
use pnet::datalink;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub fn run() {
    select_interface();
}

fn select_interface() {
    let interfaces = datalink::interfaces();
    let wireless_interfaces: Vec<_> = interfaces
        .iter()
        .filter(|iface| iface.name.starts_with("wl") || iface.name.contains("wlan"))
        .collect();

    if wireless_interfaces.is_empty() {
        println!("No wireless interfaces found.");
        return;
    }

    let interface_names: Vec<String> = wireless_interfaces
        .iter()
        .map(|iface| format!("{} ({})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Wireless Interface")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let selected_interface = wireless_interfaces[selection].name.clone();
    monitor_mode_menu(&selected_interface);
}

fn monitor_mode_menu(interface: &str) {
    loop {
        let is_monitor = check_monitor_mode(interface);
        
        let status = if is_monitor {
            "Monitor Mode: ENABLED"
        } else {
            "Monitor Mode: DISABLED"
        };

        let options = vec![
            "Put into Monitor Mode",
            "Put out of Monitor Mode",
            "Back",
        ];

        println!("\nInterface: {}", interface);
        println!("{}\n", status);

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Monitor Mode Configuration")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();

        match options[selection] {
            "Put into Monitor Mode" => {
                if let Some(new_interface) = enable_monitor_mode(interface) {
                    // Recursively call with the new interface name
                    monitor_mode_menu(&new_interface);
                    return;
                }
            }
            "Put out of Monitor Mode" => {
                if let Some(new_interface) = disable_monitor_mode(interface) {
                    // Recursively call with the new interface name
                    monitor_mode_menu(&new_interface);
                    return;
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

fn get_monitor_interface(base_interface: &str) -> Option<String> {
    // Check common monitor interface naming patterns
    let possible_names = vec![
        format!("{}mon", base_interface),
        "mon0".to_string(),
        base_interface.to_string(),
    ];

    for name in possible_names {
        if interface_exists(&name) && check_monitor_mode(&name) {
            return Some(name);
        }
    }

    None
}

fn get_managed_interface(monitor_interface: &str) -> Option<String> {
    // Remove 'mon' suffix if present
    if monitor_interface.ends_with("mon") {
        let base = monitor_interface.trim_end_matches("mon");
        if interface_exists(base) && !check_monitor_mode(base) {
            return Some(base.to_string());
        }
    }

    // Check if it's mon0, try to find wlan0
    if monitor_interface == "mon0" {
        if interface_exists("wlan0") && !check_monitor_mode("wlan0") {
            return Some("wlan0".to_string());
        }
    }

    None
}

fn enable_monitor_mode(interface: &str) -> Option<String> {
    println!("Enabling monitor mode on {}...", interface);
    
    // Kill interfering processes
    let _ = Command::new("airmon-ng")
        .args(&["check", "kill"])
        .status();

    // Start monitor mode
    let status = Command::new("airmon-ng")
        .args(&["start", interface])
        .status();

    if status.is_ok() {
        println!("Monitor mode enabled successfully!");
        thread::sleep(Duration::from_secs(2));
        
        // Try to find the new monitor interface
        if let Some(mon_interface) = get_monitor_interface(interface) {
            println!("Monitor interface detected: {}", mon_interface);
            return Some(mon_interface);
        } else {
            println!("Warning: Could not detect monitor interface.");
            println!("It may be named {}mon or mon0", interface);
            return None;
        }
    } else {
        println!("Error: Failed to enable monitor mode.");
        println!("Make sure airmon-ng is installed (aircrack-ng suite).");
        return None;
    }
}

fn disable_monitor_mode(interface: &str) -> Option<String> {
    println!("Disabling monitor mode on {}...", interface);
    
    let status = Command::new("airmon-ng")
        .args(&["stop", interface])
        .status();

    if status.is_ok() {
        println!("Monitor mode disabled successfully!");
        thread::sleep(Duration::from_secs(2));
        
        // Try to find the managed interface
        if let Some(managed_interface) = get_managed_interface(interface) {
            println!("Managed interface detected: {}", managed_interface);
            return Some(managed_interface);
        } else {
            println!("Warning: Could not detect managed interface.");
            return None;
        }
    } else {
        println!("Error: Failed to disable monitor mode.");
        return None;
    }
}
