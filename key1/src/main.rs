use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    process,
};
use rpassword::read_password;

const SALT: &str = "MY_HARD_CODED_SALT";
const MAX_KEY_SIZE: u64 = 5_000_000_000; // 5 GB
const BLOCK_SIZE: usize = 32; // 32 bytes for each SHA-256 output

fn main() {
    if let Err(err) = run() {
        // If there's an error, we log it and print a short message to stderr.
        log_error(&err.to_string());
        eprintln!("An error occurred. Check error.txt for details.");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err("Usage: key_maker <length_in_bytes>".into());
    }

    // 1) Parse desired length in bytes
    let length: u64 = args[1].parse().map_err(|_| "length_in_bytes must be a valid integer.")?;

    // 2) Check bounds
    if length < 1 || length > MAX_KEY_SIZE {
        return Err(format!(
            "length_in_bytes must be between 1 and {} (5 GB).",
            MAX_KEY_SIZE
        )
        .into());
    }

    // 3) Prompt user for password (not echoed)
    println!("Enter password (will not be echoed):");
    let password = read_password()?;

    println!("Generating key of {} bytes...", length);

    // 4) Open "key.key" for writing
    let file = File::create("key.key")
        .map_err(|_| "Failed to create 'key.key' file in current directory.")?;
    let mut writer = BufWriter::new(file);

    // 5) Write bytes in a streaming fashion to avoid large memory usage
    let mut total_written: u64 = 0;
    let mut block_index: u64 = 0;

    while total_written < length {
        // next 32 bytes come from SHA-256(password + SALT + block_index)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(SALT.as_bytes());
        hasher.update(block_index.to_le_bytes());
        let block_hash = hasher.finalize();

        // How many bytes do we still need to write?
        let remaining = length - total_written;
        let to_write = std::cmp::min(remaining, BLOCK_SIZE as u64) as usize;

        writer.write_all(&block_hash[..to_write])?;

        total_written += to_write as u64;
        block_index += 1;
    }

    writer.flush()?;

    println!("Successfully wrote {} bytes to 'key.key'.", total_written);

    Ok(())
}

/// Log an error message to "error.txt" in the current directory.
/// If opening/writing to error.txt fails, we do nothing more than swallow that error.
fn log_error(msg: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("error.txt")
    {
        let _ = writeln!(file, "{}", msg);
    }
}
