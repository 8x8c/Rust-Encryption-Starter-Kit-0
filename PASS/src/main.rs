use chacha20poly1305::aead::{Aead, KeyInit, generic_array::GenericArray};
use chacha20poly1305::ChaCha20Poly1305;
use scrypt::{scrypt, Params as ScryptParams};
use rand::RngCore;
use std::env;
use std::fs;
use std::process;

fn main() {
    // Expecting command-line arguments:
    // Usage: passphrase_encryptor E|D <input_file> <output_file> <password>
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} E|D <input_file> <output_file> <password>", args[0]);
        process::exit(1);
    }

    let command = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];
    let password = args[4].as_bytes();

    if command == "E" {
        if let Err(e) = encrypt_file(input_file, output_file, password) {
            eprintln!("Encryption error: {}", e);
            process::exit(1);
        }
    } else if command == "D" {
        if let Err(e) = decrypt_file(input_file, output_file, password) {
            eprintln!("Decryption error: {}", e);
            process::exit(1);
        }
    } else {
        eprintln!("Unknown command: {}. Use E for encrypt or D for decrypt.", command);
        process::exit(1);
    }
}

/// Derives a 32-byte key from the provided password and salt using scrypt.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let params = ScryptParams::new(15, 8, 1, 32).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    scrypt(password, salt, &params, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

/// Encrypts the file at `input_path` and writes the output (salt, nonce, ciphertext) to `output_path`.
fn encrypt_file(input_path: &str, output_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Read plaintext from input file.
    let plaintext = fs::read(input_path)?;

    // Generate a random 16-byte salt and a 12-byte nonce.
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive the encryption key.
    let key = derive_key(password, &salt)?;
    let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&key));

    // Encrypt the plaintext.
    let ciphertext = aead.encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    // Write the salt, nonce, and ciphertext to the output file.
    // File format: [salt (16 bytes)] [nonce (12 bytes)] [ciphertext]
    let mut output_data = Vec::new();
    output_data.extend_from_slice(&salt);
    output_data.extend_from_slice(&nonce);
    output_data.extend_from_slice(&ciphertext);
    fs::write(output_path, output_data)?;

    Ok(())
}

/// Decrypts the file at `input_path` (which should have salt, nonce, and ciphertext)
/// and writes the decrypted data to `output_path`.
fn decrypt_file(input_path: &str, output_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;

    // Ensure the file is long enough to contain the salt and nonce.
    if data.len() < 16 + 12 {
        return Err("Input file is too short to contain the necessary header.".into());
    }

    // Split the data into salt, nonce, and ciphertext.
    let salt = &data[0..16];
    let nonce = &data[16..28];
    let ciphertext = &data[28..];

    // Derive the key from the password and salt.
    let key = derive_key(password, salt)?;
    let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&key));

    // Decrypt the ciphertext.
    let plaintext = aead.decrypt(GenericArray::from_slice(nonce), ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    // Write the plaintext to the output file.
    fs::write(output_path, plaintext)?;

    Ok(())
}


