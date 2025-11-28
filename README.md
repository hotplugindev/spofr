# Spofr - Network Spoofing Tool

**DISCLAIMER: This tool is for EDUCATIONAL PURPOSES ONLY. The author is not responsible for any misuse of this tool. Ensure you have permission to test on the network you are using.**

Spofr is a Rust-based command-line tool designed to demonstrate network spoofing attacks, specifically ARP spoofing. It provides a user-friendly terminal interface to list network interfaces, configure attack parameters, and execute spoofing attacks.

## Features

### ARP Spoofer
The ARP (Address Resolution Protocol) module allows you to intercept traffic between a target and the gateway.

*   **List Network Settings**: 
    *   View detailed information about all network interfaces.
    *   Displays IP addresses, subnet masks, calculated network and broadcast addresses.
    *   Shows MAC addresses, interface flags (UP, RUNNING, etc.), and MTU.
    *   Attempts to detect the default gateway and DNS servers.
*   **Set Network Settings**:
    *   **Manual Configuration**: Manually specify the interface, default gateway, and target IP.
    *   **Auto-Configuration**: Automatically detects the gateway and sets the target to the entire network (broadcast).
*   **Start Attack**:
    *   Performs ARP spoofing based on the configuration.
    *   Supports single target spoofing (Target <-> Gateway).
    *   Supports entire network spoofing (Gratuitous ARP broadcast).
    *   **Note**: Requires `root` privileges to send raw packets and enable IP forwarding.

### DHCP Spoofer
The DHCP (Dynamic Host Configuration Protocol) module allows you to deploy a rogue DHCP server to intercept traffic or cause denial of service.

*   **List Network Settings**: 
    *   View detailed information about network interfaces to help select the correct one for the attack.
*   **Set Network Settings**:
    *   **Router (Gateway) IP**: Configure the IP address that victims should use as their gateway (usually your IP or the real gateway if performing MITM).
    *   **Pool Configuration**: Set the Start and End IP addresses for the address pool.
    *   **DNS Server**: Specify the DNS server to provide to victims (e.g., a malicious DNS or 8.8.8.8).
    *   **Auto-Suggestion**: The tool attempts to guess reasonable defaults based on the selected interface's current configuration.
*   **Start Attack**:
    *   Starts a raw socket listener on UDP port 67.
    *   Responds to **DHCP Discover** messages with **DHCP Offer** (offering an IP from the pool).
    *   Responds to **DHCP Request** messages with **DHCP Ack** (confirming the lease).
    *   **Note**: This effectively races the legitimate DHCP server. If your server is faster, victims will accept your configuration.

## Usage

1.  **Build**:
    ```bash
    cargo build --release
    ```

2.  **Run (requires root)**:
    ```bash
    sudo ./target/release/spofr
    ```
    Or with cargo (for development):
    ```bash
    sudo cargo run
    ```

## Requirements
*   Linux (uses `/proc` and `/sys` filesystems for some info).
*   Root privileges (for raw socket access).

## Educational Value
This tool demonstrates how the lack of authentication in ARP can be exploited to redirect network traffic. It serves as a practical example for learning about:
*   Network protocols (ARP, Ethernet, IP).
*   Raw socket programming in Rust.
*   Network security and mitigation strategies (e.g., dynamic ARP inspection).
