use std::env;
use std::fs;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use rpassword::prompt_password;

// Compile‑time constants for deterministic key generation.
// You can override these by setting the environment variables `CHAGEN_SALT` and `CHAGEN_PEPPER` at compile time.
const SALT: &str = match option_env!("CHAGEN_SALT") {
    Some(s) => s,
    None => "default_salt",
};

const PEPPER: &str = match option_env!("CHAGEN_PEPPER") {
    Some(s) => s,
    None => "default_pepper",
};

/// Generates a 32‑byte key using the OS random number generator.
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generates a deterministic 32‑byte key by prompting the user for a password and hashing it along with
/// the compile‑time salt and pepper.
fn generate_deterministic_key_with_password() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let password = prompt_password("Enter password: ")?;
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(SALT.as_bytes());
    hasher.update(PEPPER.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// Writes the generated key to a file named "key.key".
fn write_key_to_file(key: &[u8]) -> std::io::Result<()> {
    fs::write("key.key", key)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Expect exactly one argument: either -R (randomized) or -D (deterministic)
    if args.len() != 2 {
        eprintln!("Usage: {} [-R | -D]", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    let key = match mode.as_str() {
        "-R" => generate_random_key(),
        "-D" => match generate_deterministic_key_with_password() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error generating deterministic key: {}", e);
                std::process::exit(1);
            }
        },
        _ => {
            eprintln!("Invalid mode. Use -R for random key generation or -D for deterministic key generation.");
            std::process::exit(1);
        }
    };

    if let Err(e) = write_key_to_file(&key) {
        eprintln!("Error writing key to file: {}", e);
        std::process::exit(1);
    }
}

