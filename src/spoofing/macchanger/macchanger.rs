use dialoguer::{theme::ColorfulTheme, Input, Select};
use pnet::datalink;
use pnet::util::MacAddr;
use std::process::Command;
use rand::Rng;

pub fn run() {
    let selections = &["Change MAC Address", "Set Random MAC", "Restore Original MAC", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("MAC Changer Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Change MAC Address" => change_mac_address(),
            "Set Random MAC" => set_random_mac(),
            "Restore Original MAC" => restore_original_mac(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn change_mac_address() {
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

    let interface = &interfaces[selection];
    
    let new_mac: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter new MAC address (e.g., 00:11:22:33:44:55)")
        .interact_text()
        .unwrap();

    if let Err(_e) = new_mac.parse::<MacAddr>() {
        println!("Invalid MAC address format.");
        return;
    }

    set_mac(&interface.name, &new_mac);
}

fn set_random_mac() {
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

    let interface = &interfaces[selection];
    
    let random_mac = generate_random_mac();
    println!("Generated random MAC: {}", random_mac);
    
    set_mac(&interface.name, &random_mac);
}

fn restore_original_mac() {
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
        .with_prompt("Select Interface to Restore")
        .default(0)
        .items(&interface_names)
        .interact()
        .unwrap();

    let interface = &interfaces[selection];
    
    println!("Bringing interface down and up to restore original MAC...");
    
    // Bring interface down and up to restore
    let _ = Command::new("ip")
        .args(&["link", "set", &interface.name, "down"])
        .status();
    
    let _ = Command::new("ip")
        .args(&["link", "set", &interface.name, "up"])
        .status();
    
    println!("Interface {} has been reset. Original MAC should be restored.", interface.name);
    println!("Note: This may not work on all systems. Check with 'ip link show {}'", interface.name);
}

fn set_mac(interface: &str, mac: &str) {
    println!("Changing MAC address for {} to {}...", interface, mac);
    
    // Bring interface down
    let down = Command::new("ip")
        .args(&["link", "set", interface, "down"])
        .status();
    
    if let Err(e) = down {
        println!("Error bringing interface down: {}", e);
        return;
    }

    // Set new MAC
    let set = Command::new("ip")
        .args(&["link", "set", interface, "address", mac])
        .status();
    
    if let Err(e) = set {
        println!("Error setting MAC address: {}", e);
        return;
    }

    // Bring interface up
    let up = Command::new("ip")
        .args(&["link", "set", interface, "up"])
        .status();
    
    if let Err(e) = up {
        println!("Error bringing interface up: {}", e);
        return;
    }

    println!("MAC address changed successfully!");
    println!("Verify with: ip link show {}", interface);
}

fn generate_random_mac() -> String {
    let mut rng = rand::rng();
    
    // First byte: Set locally administered bit (bit 1) and unicast (bit 0 = 0)
    // This ensures it's a valid MAC that won't conflict with manufacturer MACs
    let first_byte = (rng.random::<u8>() & 0xFE) | 0x02;
    
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        first_byte,
        rng.random::<u8>(),
        rng.random::<u8>(),
        rng.random::<u8>(),
        rng.random::<u8>(),
        rng.random::<u8>()
    )
}
