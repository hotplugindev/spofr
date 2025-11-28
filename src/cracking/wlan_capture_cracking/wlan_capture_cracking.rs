use dialoguer::{theme::ColorfulTheme, Select, Input, Confirm};
use std::process::{Command, Stdio};
use std::path::Path;
use std::fs;

pub fn run() {
    let selections = &["Crack Capture File", "Back"];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("WLAN Capture Cracking Menu")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selections[selection] {
            "Crack Capture File" => crack_capture(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn crack_capture() {
    // Get capture file path
    let capture_file = match Input::<String>::new()
        .with_prompt("Enter path to capture file (.cap)")
        .default("/tmp/handshake-01.cap".to_string())
        .interact()
    {
        Ok(path) => path,
        Err(_) => return,
    };

    // Validate file exists
    if !Path::new(&capture_file).exists() {
        println!("\nError: File '{}' does not exist!", capture_file);
        
        let options = vec!["Back"];
        let _selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Press Enter to go back")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();
        return;
    }

    // Ask for cracking mode
    let mode_options = vec![
        "Use wordlist file",
        "Brute force (try all combinations)",
    ];

    let mode_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select cracking mode")
        .default(0)
        .items(&mode_options[..])
        .interact()
        .unwrap();

    match mode_options[mode_selection] {
        "Use wordlist file" => crack_with_wordlist(&capture_file),
        "Brute force (try all combinations)" => crack_bruteforce(&capture_file),
        _ => unreachable!(),
    }
}

fn crack_with_wordlist(capture_file: &str) {
    // Get wordlist file path
    let wordlist = match Input::<String>::new()
        .with_prompt("Enter path to wordlist file")
        .default("/usr/share/wordlists/rockyou.txt".to_string())
        .interact()
    {
        Ok(path) => path,
        Err(_) => return,
    };

    // Validate wordlist exists
    if !Path::new(&wordlist).exists() {
        println!("\nError: Wordlist file '{}' does not exist!", wordlist);
        
        // Suggest common wordlist locations
        println!("\nCommon wordlist locations:");
        println!("  - /usr/share/wordlists/rockyou.txt");
        println!("  - /usr/share/wordlists/fasttrack.txt");
        println!("  - /usr/share/john/password.lst");
        
        let options = vec!["Back"];
        let _selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Press Enter to go back")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();
        return;
    }

    // Get number of lines in wordlist
    let wordlist_size = count_lines(&wordlist);
    println!("\nWordlist contains approximately {} passwords", wordlist_size);

    // Confirm before starting
    let confirm = Confirm::new()
        .with_prompt("Start cracking?")
        .default(true)
        .interact()
        .unwrap_or(false);

    if !confirm {
        return;
    }

    println!("\n=== Starting WPA/WPA2 Cracking ===");
    println!("Capture file: {}", capture_file);
    println!("Wordlist: {}", wordlist);
    println!("\nThis may take a while depending on the wordlist size...");
    println!("Press Ctrl+C to stop.\n");

    // Run aircrack-ng with wordlist
    let status = Command::new("aircrack-ng")
        .args(&[
            "-w", &wordlist,
            "-b", "-",  // Try all BSSIDs in the file
            capture_file
        ])
        .status();

    match status {
        Ok(exit_status) => {
            if exit_status.success() {
                println!("\n=== Cracking completed successfully! ===");
                println!("Check the output above for the password.");
            } else {
                println!("\n=== Cracking process ended ===");
                println!("Password may not have been found in the wordlist.");
            }
        }
        Err(e) => {
            println!("\nError: Failed to run aircrack-ng: {}", e);
            println!("Make sure aircrack-ng is installed (aircrack-ng suite).");
        }
    }

    // Wait for user to press enter
    let options = vec!["Back"];
    let _selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Press Enter to continue")
        .default(0)
        .items(&options[..])
        .interact()
        .unwrap();
}

fn crack_bruteforce(capture_file: &str) {
    println!("\n=== Brute Force Configuration ===");
    
    // Get minimum password length
    let min_len = match Input::<usize>::new()
        .with_prompt("Minimum password length")
        .default(8)
        .interact()
    {
        Ok(len) => len,
        Err(_) => return,
    };

    // Get maximum password length
    let max_len = match Input::<usize>::new()
        .with_prompt("Maximum password length")
        .default(10)
        .interact()
    {
        Ok(len) => len,
        Err(_) => return,
    };

    // Get character set
    let charset_options = vec![
        "Lowercase only (a-z)",
        "Lowercase + uppercase (a-z, A-Z)",
        "Alphanumeric (a-z, A-Z, 0-9)",
        "All printable characters",
        "Numeric only (0-9)",
    ];

    let charset_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select character set")
        .default(2)
        .items(&charset_options[..])
        .interact()
        .unwrap();

    let charset = match charset_options[charset_selection] {
        "Lowercase only (a-z)" => "?l",
        "Lowercase + uppercase (a-z, A-Z)" => "?l?u",
        "Alphanumeric (a-z, A-Z, 0-9)" => "?l?u?d",
        "All printable characters" => "?l?u?d?s",
        "Numeric only (0-9)" => "?d",
        _ => "?l?u?d",
    };

    println!("\nWARNING: Brute force cracking can take an extremely long time!");
    println!("For example:");
    println!("  - 8 character alphanumeric: ~218 trillion combinations");
    println!("  - 10 character alphanumeric: ~839 quadrillion combinations");
    println!("\nConsider using a wordlist instead for practical cracking.\n");

    // Confirm before starting
    let confirm = Confirm::new()
        .with_prompt("Are you sure you want to continue?")
        .default(false)
        .interact()
        .unwrap_or(false);

    if !confirm {
        return;
    }

    println!("\n=== Starting Brute Force Cracking ===");
    println!("Capture file: {}", capture_file);
    println!("Password length: {} to {}", min_len, max_len);
    println!("Character set: {}", charset);
    println!("\nThis will likely take a VERY long time...");
    println!("Press Ctrl+C to stop.\n");

    // Generate mask for crux/hashcat style brute force
    // Note: aircrack-ng doesn't support true brute force natively
    // We'll need to use crunch to generate passwords on-the-fly
    
    println!("Generating passwords with crunch and piping to aircrack-ng...\n");

    for len in min_len..=max_len {
        println!("Trying passwords of length {}...", len);
        
        // Build pattern for crunch
        let charset_expanded = match charset {
            "?l" => "abcdefghijklmnopqrstuvwxyz",
            "?d" => "0123456789",
            "?l?u" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "?l?u?d" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "?l?u?d?s" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?",
            _ => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        };

        // Use crunch to generate passwords and pipe to aircrack-ng
        let crunch = Command::new("crunch")
            .args(&[&len.to_string(), &len.to_string(), charset_expanded])
            .stdout(Stdio::piped())
            .spawn();

        if let Ok(mut crunch_child) = crunch {
            if let Some(stdout) = crunch_child.stdout.take() {
                let aircrack = Command::new("aircrack-ng")
                    .args(&[
                        "-w", "-",  // Read from stdin
                        "-b", "-",  // Try all BSSIDs
                        capture_file
                    ])
                    .stdin(stdout)
                    .status();

                match aircrack {
                    Ok(exit_status) => {
                        if exit_status.success() {
                            println!("\n=== Password found! ===");
                            println!("Check the output above for the password.");
                            let _ = crunch_child.kill();
                            break;
                        }
                    }
                    Err(e) => {
                        println!("\nError running aircrack-ng: {}", e);
                        let _ = crunch_child.kill();
                        break;
                    }
                }
            }
            let _ = crunch_child.kill();
        } else {
            println!("\nError: Failed to run crunch.");
            println!("Make sure crunch is installed: sudo apt install crunch");
            break;
        }
    }

    // Wait for user to press enter
    let options = vec!["Back"];
    let _selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Press Enter to continue")
        .default(0)
        .items(&options[..])
        .interact()
        .unwrap();
}

fn count_lines(filepath: &str) -> usize {
    match fs::read_to_string(filepath) {
        Ok(contents) => contents.lines().count(),
        Err(_) => {
            // If file is too large to read, estimate with wc
            let output = Command::new("wc")
                .args(&["-l", filepath])
                .output();
            
            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(count_str) = stdout.split_whitespace().next() {
                    return count_str.parse().unwrap_or(0);
                }
            }
            0
        }
    }
}
