mod arp;
mod dhcp;

use dialoguer::{theme::ColorfulTheme, Select};

fn main() {
    let selections = &["Arp", "Dhcp", "Exit"];

    println!("Welcome to the Network Tool");

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Arp" => arp::arp::run(),
            "Dhcp" => dhcp::dhcp::run(),
            "Exit" => {
                println!("Exiting...");
                break;
            }
            _ => unreachable!(),
        }
    }
}
