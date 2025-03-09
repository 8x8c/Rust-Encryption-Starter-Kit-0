use std::fs;
use std::path::Path;
use std::process;

use clap::{Arg, ArgAction, Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("hash2key")
        .version("1.0")
        .about("Takes a SHA3-256 hash (64 hex chars) and writes it into key.key")
        .arg(
            Arg::new("hash")
                .required(true)
                .action(ArgAction::Set)
                .help("The 64-hex-character SHA3-256 hash"),
        )
        .get_matches();

    // Retrieve the provided hash string
    let hash_hex = matches.get_one::<String>("hash").unwrap().trim().to_lowercase();

    // Ensure the string length is exactly 64 characters (32 bytes in hex)
    if hash_hex.len() != 64 {
        eprintln!("Error: hash must be exactly 64 hex characters. Received length: {}", hash_hex.len());
        process::exit(1);
    }

    // Ensure the output file doesn't already exist
    let key_path = Path::new("key.key");
    if key_path.exists() {
        eprintln!("Error: key.key already exists. Aborting to avoid overwriting.");
        process::exit(1);
    }

    // Convert the hex string to bytes
    let key_bytes = hex::decode(&hash_hex)
        .map_err(|_| "Invalid hex in the supplied hash. Make sure it's valid 64-character hex.")?;

    // Sanity check: Should be exactly 32 bytes
    if key_bytes.len() != 32 {
        eprintln!("Error: The decoded hash must be exactly 32 bytes, but got {}", key_bytes.len());
        process::exit(1);
    }

    // Write key.key file
    fs::write(&key_path, &key_bytes)?;
    println!("key.key has been created from the provided SHA3-256 hash.");

    Ok(())
}

