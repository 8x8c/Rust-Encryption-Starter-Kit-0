use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce}; // Nonce size is 12-bytes
use clap::{App, Arg};
use rand::RngCore;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up CLI argument parsing with clap.
    let matches = App::new("Secure File Encryptor")
        .version("1.0")
        .about("Encrypts and decrypts files using AES-256-GCM")
        .arg(
            Arg::with_name("encrypt")
                .short("e")
                .help("Encrypt the file")
                .conflicts_with("decrypt")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .help("Decrypt the file")
                .conflicts_with("encrypt")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("input")
                .help("Input file path")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("output")
                .help("Output file path")
                .required(true)
                .index(2),
        )
        .get_matches();

    let encrypt_mode = matches.is_present("encrypt");
    let decrypt_mode = matches.is_present("decrypt");

    let input_file = matches.value_of("input").unwrap();
    let output_file = matches.value_of("output").unwrap();

    // Load the key from "key.key" or generate it if not present.
    let key = load_or_generate_key()?;

    // Initialize the AES-256-GCM cipher with the key.
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Failed to create cipher instance")?;

    if encrypt_mode {
        // Read the plaintext from the input file.
        let plaintext = fs::read(input_file)?;
        
        // Generate a random 12-byte nonce using a secure RNG.
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext. The encrypt method returns ciphertext.
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        // Write the nonce and the ciphertext to the output file.
        // The nonce is prepended to the ciphertext so it can be used for decryption.
        let mut out_file = File::create(output_file)?;
        out_file.write_all(&nonce_bytes)?;
        out_file.write_all(&ciphertext)?;
        println!("File encrypted successfully.");

    } else if decrypt_mode {
        // Read the entire content from the input file.
        let data = fs::read(input_file)?;
        if data.len() < 12 {
            return Err("Ciphertext file is too short to contain a valid nonce.".into());
        }
        // Split out the nonce and ciphertext.
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the ciphertext.
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("Decryption error: {:?}", e))?;
        
        // Write the resulting plaintext to the output file.
        fs::write(output_file, plaintext)?;
        println!("File decrypted successfully.");

    } else {
        eprintln!("Please specify either -e for encryption or -d for decryption.");
    }

    Ok(())
}

/// Loads a 32-byte key from "key.key". If the file does not exist, a new key is generated,
/// written to "key.key", and returned.
fn load_or_generate_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_path = Path::new("key.key");
    if key_path.exists() {
        let key = fs::read(key_path)?;
        if key.len() != 32 {
            return Err("Invalid key length in key.key; expected 32 bytes.".into());
        }
        Ok(key)
    } else {
        // Generate a new 32-byte key using a secure random number generator.
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        fs::write(key_path, &key)?;
        println!("No key.key found. Generated a new key and saved to key.key.");
        Ok(key.to_vec())
    }
}

