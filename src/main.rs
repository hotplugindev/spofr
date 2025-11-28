mod spoofing;
mod wireless;
mod cracking;

use dialoguer::{theme::ColorfulTheme, Select};

fn main() {
    let selections = &["Wireless", "Spoof Attacks", "Cracking", "Exit"];

    println!("Welcome to Spofr - Educational Network Tool");

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Main Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Wireless" => wireless_menu(),
            "Spoof Attacks" => spoof_attacks_menu(),
            "Cracking" => cracking_menu(),
            "Exit" => {
                println!("Exiting...");
                break;
            }
            _ => unreachable!(),
        }
    }
}

fn wireless_menu() {
    let selections = &["Change Card Mode", "WLAN Jammer", "Auth Capture", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Wireless Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Change Card Mode" => wireless::card_mode::card_mode::run(),
            "WLAN Jammer" => wireless::wlan_jammer::wlan_jammer::run(),
            "Auth Capture" => wireless::auth_capture::auth_capture::run(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn spoof_attacks_menu() {
    let selections = &["ARP Spoofer", "DHCP Spoofer", "DNS Spoofer", "MAC Changer", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Spoof Attacks Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "ARP Spoofer" => spoofing::arp::arp::run(),
            "DHCP Spoofer" => spoofing::dhcp::dhcp::run(),
            "DNS Spoofer" => spoofing::dns::dns::run(),
            "MAC Changer" => spoofing::macchanger::macchanger::run(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn cracking_menu() {
    let selections = &["WLAN Capture Cracking", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Cracking Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "WLAN Capture Cracking" => cracking::wlan_capture_cracking::wlan_capture_cracking::run(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}
