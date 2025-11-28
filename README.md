# Spofr - Educational Network Hacking Collection

## ⚠️ DISCLAIMER - EDUCATIONAL PURPOSES ONLY ⚠️

**THIS TOOL IS STRICTLY FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY.**

The author is **NOT** responsible for any misuse of this tool. Unauthorized access to computer networks is illegal. Always ensure you have explicit permission to test on any network or system you are targeting. This tool is designed to help security professionals, students, and enthusiasts learn about network security concepts and vulnerabilities.

**USE AT YOUR OWN RISK. ALWAYS RESPECT THE LAW AND OTHERS' PRIVACY.**

---

## About

Spofr is a Rust-based educational network security toolkit that demonstrates various network attack techniques. It provides a command-line interface to explore and understand how network protocols can be exploited, and serves as a practical learning resource for understanding network security vulnerabilities and defenses.

## Features

### 🎯 Spoof Attacks

#### ARP Spoofer
Address Resolution Protocol (ARP) spoofing attack implementation.

*   **List Network Settings**: 
    *   View comprehensive information about all network interfaces.
    *   Displays IP addresses, subnet masks, calculated network and broadcast addresses.
    *   Shows MAC addresses, interface flags (UP, RUNNING, PROMISC, etc.), and MTU.
    *   Attempts to detect the default gateway and DNS servers.
*   **Set Network Settings**:
    *   **Manual Configuration**: Manually specify the interface, default gateway, and target IP.
    *   **Auto-Configuration**: Automatically detects the gateway and sets the target to the entire network.
*   **Start Attack**:
    *   Performs ARP spoofing based on the configuration.
    *   Supports single target spoofing (Man-in-the-Middle between Target and Gateway).
    *   Supports entire network spoofing (Gratuitous ARP broadcast).
    *   Automatically enables IP forwarding to allow traffic to pass through.
    *   **Requires**: `root` privileges for raw packet manipulation.

#### DHCP Spoofer
Rogue DHCP server implementation for network takeover attacks.

*   **List Network Settings**: 
    *   View detailed information about network interfaces.
*   **Set Network Settings**:
    *   Configure **Router (Gateway) IP**: The IP address victims will use as their gateway.
    *   **Pool Configuration**: Define the Start and End IP addresses for the address pool.
    *   **DNS Server**: Specify DNS server to provide to victims.
    *   **Auto-Suggestion**: Intelligent defaults based on selected interface configuration.
*   **Start Attack**:
    *   Starts a raw socket listener on UDP port 67.
    *   Responds to **DHCP Discover** messages with **DHCP Offer**.
    *   Responds to **DHCP Request** messages with **DHCP Ack**.
    *   Races against legitimate DHCP servers to control network configuration.
    *   **Requires**: `root` privileges for raw socket access.

#### DNS Spoofer
Domain Name System (DNS) spoofing attack for traffic redirection.

*   **List Network Settings**: 
    *   View comprehensive interface information including IP addresses and DNS servers.
    *   Displays detected gateway and DNS configuration.
*   **Set Network Settings**:
    *   **Manual Configuration**: Specify interface and target (specific IP or entire network).
    *   **Auto-Configuration**: Automatically configures for network-wide DNS poisoning.
*   **Configure DNS Mappings**:
    *   **Redirect to IP**: Map specific domains to IP addresses (e.g., example.com -> 192.168.1.100).
    *   **Redirect to Domain**: Redirect one domain to another (resolves target domain via system DNS).
    *   **Wildcard Catch-All**: Map all unmatched domains to a single IP address.
    *   **Multiple Mappings**: Support for numerous domain-to-IP mappings simultaneously.
    *   **Mapping Management**: Add, remove, or clear all mappings interactively.
*   **Start Attack**:
    *   Intercepts DNS queries (UDP port 53) on the network.
    *   Responds with spoofed DNS responses before legitimate DNS servers.
    *   Supports both targeted (specific host) and broadcast (entire network) spoofing.
    *   Real-time logging of spoofed queries.
    *   **Requires**: `root` privileges for packet manipulation.

#### MAC Changer
Network interface MAC address manipulation tool.

*   **Change MAC Address**: Set a custom MAC address for any network interface.
*   **Set Random MAC**: Generate and apply a random, valid MAC address.
*   **Restore Original MAC**: Reset interface to restore the original hardware MAC address.
*   **Features**:
    *   Validates MAC address format.
    *   Generates locally administered MAC addresses to avoid conflicts.
    *   Manages interface state (down/up) automatically.
    *   **Requires**: `root` privileges for interface configuration.

### 📡 Wireless Attacks

#### Change Card Mode
WiFi interface monitor mode configuration tool.

*   **Interface Selection**: Lists all wireless network interfaces.
*   **Monitor Mode Management**:
    *   **Enable Monitor Mode**: Uses `airmon-ng` to put interface into monitor mode.
    *   **Disable Monitor Mode**: Restores interface to managed mode.
    *   **Status Checking**: Real-time monitor mode status display.
    *   **Interface Detection**: Automatically detects renamed monitor interfaces (wlan0mon, mon0, etc.).
*   **Requirements**: `aircrack-ng` suite (airmon-ng) must be installed.

#### WLAN Jammer
WiFi deauthentication attack tool for network disruption testing.

*   **Interface Selection**: Automatically detects wireless interfaces and displays their mode status.
*   **Network Scanning**:
    *   Scans for available WiFi networks using `airodump-ng`.
    *   Displays ESSID, BSSID, Channel, and Signal Power.
    *   Interactive network selection.
*   **Jamming Attack**:
    *   Performs continuous deauthentication attack using `aireplay-ng`.
    *   Targets all clients connected to selected access point.
    *   Automatically sets correct channel for attack.
    *   **Requires**: Monitor mode must be enabled first using "Change Card Mode".

#### Auth Capture
WPA/WPA2 handshake capture tool for password cracking preparation.

*   **Interface Selection**: Detects and validates monitor mode interfaces.
*   **Network Scanning**: Scans and selects target WiFi network.
*   **Capture Configuration**:
    *   **Set Output Path**: Customize capture file destination (default: `/tmp/handshake`).
    *   **Active Capture**: Sends deauthentication packets to force handshake.
    *   **Passive Capture**: Waits for natural client reconnection to capture handshake.
*   **Handshake Capture**:
    *   Uses `airodump-ng` to capture WPA/WPA2 4-way handshake.
    *   Saves capture in `.cap` format for later cracking.
    *   Real-time capture monitoring.
    *   **Requires**: Monitor mode enabled, `aircrack-ng` suite installed.

### 🔓 Cracking

#### WLAN Capture Cracking
WPA/WPA2 password recovery tool using captured handshakes.

*   **Capture File Selection**: Specify path to captured `.cap` file.
*   **Cracking Modes**:
    *   **Wordlist Attack**:
        *   Uses dictionary/wordlist file to test passwords.
        *   Supports large wordlists (rockyou.txt, etc.).
        *   Displays wordlist size before starting.
        *   Fast and practical for common passwords.
    *   **Brute Force Attack**:
        *   Systematically tries all possible password combinations.
        *   Configurable password length (min/max).
        *   Multiple character sets:
            *   Lowercase only (a-z)
            *   Lowercase + uppercase (a-z, A-Z)
            *   Alphanumeric (a-z, A-Z, 0-9)
            *   All printable characters
            *   Numeric only (0-9)
        *   Uses `crunch` to generate passwords on-the-fly.
        *   Warning system about extreme time requirements.
*   **Tools Used**: `aircrack-ng` for cracking, `crunch` for password generation.
*   **Common Wordlists**:
    *   `/usr/share/wordlists/rockyou.txt`
    *   `/usr/share/wordlists/fasttrack.txt`
    *   `/usr/share/john/password.lst`

## Installation

### From crates.io

```bash
cargo install spofr
```

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/hotplugindev/spofr
    cd spofr
    ```

2.  Build the project:
    ```bash
    cargo build --release
    ```

## Usage

**Root privileges are required for most features:**

```bash
sudo spofr
```

Or if installed via cargo:

```bash
sudo $(which spofr)
```

The tool will present an interactive menu where you can navigate through different attack modules.

## Requirements

*   **Operating System**: Linux (uses `/proc`, `/sys`, and `ip` command)
*   **Privileges**: Root access required for raw socket operations and network interface manipulation
*   **Rust**: Edition 2021 or later
*   **Required Tools**: 
    *   `aircrack-ng` suite (airmon-ng, airodump-ng, aireplay-ng) for wireless features
    *   `crunch` for brute force password generation (optional, for cracking module)
*   **Recommended Wordlists**:
    *   rockyou.txt (`sudo apt install wordlists` or download separately)
    *   Custom wordlists for targeted attacks

## Educational Value

This tool demonstrates:

*   **ARP Protocol Vulnerabilities**: Understanding how the lack of authentication in ARP can be exploited.
*   **DHCP Security**: How rogue DHCP servers can compromise network security.
*   **DNS Spoofing**: Man-in-the-middle attacks through DNS cache poisoning and response manipulation.
*   **MAC Address Spoofing**: Bypassing MAC-based access controls.
*   **WiFi Security Protocols**: Understanding WPA/WPA2 4-way handshake capture and vulnerabilities.
*   **Password Cracking Techniques**: Dictionary attacks vs. brute force approaches.
*   **Monitor Mode Operations**: Understanding wireless packet injection and monitoring.
*   **Raw Socket Programming**: Low-level network packet manipulation in Rust.
*   **Network Security Concepts**: Practical implementation of common attack vectors.

## Implemented Features Summary

✅ **ARP Spoofing** - Full implementation with auto and manual configuration  
✅ **DHCP Spoofing** - Rogue DHCP server with complete DORA handshake  
✅ **DNS Spoofing** - DNS cache poisoning with flexible domain mapping and redirection  
✅ **MAC Changer** - Custom and random MAC address assignment  
✅ **Change Card Mode** - Monitor mode management for wireless interfaces  
✅ **WLAN Jammer** - WiFi deauthentication attack  
✅ **Auth Capture** - WPA/WPA2 handshake capture with active and passive modes  
✅ **WLAN Capture Cracking** - Password recovery with wordlist and brute force attacks

## Contributing

Contributions are welcome! Please ensure all contributions maintain the educational focus and include appropriate warnings about legal and ethical use.

## License

MIT License - See LICENSE file for details

## Legal Notice

This software is provided for educational purposes. Users must comply with all applicable laws and regulations in their jurisdiction. Unauthorized network intrusion is illegal. Always obtain proper authorization before testing network security.
