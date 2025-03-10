use std::fs;
use std::path::Path;
use std::process;

use clap::{Arg, Command, ArgAction};
use sha3::{Digest, Sha3_256};

use chacha20poly1305::{
    aead::Aead,
    Key, XNonce, XChaCha20Poly1305, KeyInit,
};
use rand::RngCore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("xchacha20poly1305-cli")
        .version("1.0")
        .about("Encrypts or decrypts files using XChaCha20-Poly1305.")
        .arg(
            Arg::new("key")
                .short('k')
                .action(ArgAction::Set)
                .value_name("PASSWORD")
                .help("Generate key.key from the given password (using SHA3-256)"),
        )
        .arg(
            Arg::new("encrypt")
                .short('e')
                .num_args(2)
                .value_names(["INPUT", "OUTPUT"])
                .help("Encrypt INPUT file to OUTPUT file"),
        )
        .arg(
            Arg::new("decrypt")
                .short('d')
                .num_args(2)
                .value_names(["INPUT", "OUTPUT"])
                .help("Decrypt INPUT file to OUTPUT file"),
        )
        .get_matches();

    // Key generation mode.
    if let Some(password) = matches.get_one::<String>("key") {
        let key_path = Path::new("key.key");
        if key_path.exists() {
            eprintln!("Error: key.key already exists. Aborting to avoid overwriting.");
            process::exit(1);
        }
        let mut hasher = Sha3_256::new();
        hasher.update(password.as_bytes());
        let key_hash = hasher.finalize();
        fs::write(key_path, &key_hash)?;
        println!("Key generated and saved to key.key");
        return Ok(());
    }

    // Encryption mode.
    if let Some(values) = matches.get_many::<String>("encrypt") {
        let values: Vec<_> = values.into_iter().collect();
        if values.len() != 2 {
            eprintln!("Error: Encryption requires exactly two arguments: INPUT and OUTPUT.");
            process::exit(1);
        }
        let input_file = values[0];
        let output_file = values[1];

        // Check if the output file already exists.
        if Path::new(output_file).exists() {
            eprintln!("Error: Output file '{}' already exists. Aborting to avoid overwriting.", output_file);
            process::exit(1);
        }

        // Load the 32-byte key.
        let key_bytes = fs::read("key.key")
            .map_err(|_| "Failed to read key.key. Please generate a key with -k [password]")?;
        if key_bytes.len() != 32 {
            return Err("Invalid key length in key.key file".into());
        }
        let key = Key::from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new(key);

        // Read the plaintext.
        let plaintext = fs::read(input_file)?;

        // Generate a random 24-byte nonce.
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext.
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        // Prepend the nonce to the ciphertext.
        let mut output_data = nonce_bytes.to_vec();
        output_data.extend_from_slice(&ciphertext);
        fs::write(output_file, output_data)?;
        println!("Encryption successful.");
        return Ok(());
    }

    // Decryption mode.
    if let Some(values) = matches.get_many::<String>("decrypt") {
        let values: Vec<_> = values.into_iter().collect();
        if values.len() != 2 {
            eprintln!("Error: Decryption requires exactly two arguments: INPUT and OUTPUT.");
            process::exit(1);
        }
        let input_file = values[0];
        let output_file = values[1];

        // Check if the output file already exists.
        if Path::new(output_file).exists() {
            eprintln!("Error: Output file '{}' already exists. Aborting to avoid overwriting.", output_file);
            process::exit(1);
        }

        // Load the key.
        let key_bytes = fs::read("key.key")
            .map_err(|_| "Failed to read key.key. Please generate a key with -k [password]")?;
        if key_bytes.len() != 32 {
            return Err("Invalid key length in key.key file".into());
        }
        let key = Key::from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new(key);

        // Read the encrypted data (nonce + ciphertext).
        let data = fs::read(input_file)?;
        if data.len() < 24 {
            return Err("Input file is too short to contain a valid nonce.".into());
        }
        let (nonce_bytes, ciphertext) = data.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        // Attempt decryption.
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;
        fs::write(output_file, plaintext)?;
        println!("Decryption successful.");
        return Ok(());
    }

    println!("No valid command provided. Use -e, -d, or -k.");
    Ok(())
}


