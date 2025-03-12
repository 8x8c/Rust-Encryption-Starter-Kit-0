use std::env;
use std::fs;
use std::io;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;

/// Reads a 32‑byte key from the "key.key" file.
fn load_key_from_file() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let key_data = fs::read("key.key")?;
    if key_data.len() != 32 {
        return Err("Invalid key length in key.key; expected 32 bytes.".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    Ok(key)
}

/// Encrypts the file at `input_path` and writes the result to `output_path`.
/// Output format: [nonce (24 bytes)] || [ciphertext]
fn encrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input_path)?;
    let key = load_key_from_file()?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut output = nonce.to_vec();
    output.extend(ciphertext);
    fs::write(output_path, output)?;
    Ok(())
}

/// Decrypts the file at `input_path` and writes the plaintext to `output_path`.
/// Expects file format: [nonce (24 bytes)] || [ciphertext]
fn decrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    if data.len() < 24 {
        return Err("Input file too short to contain a valid nonce.".into());
    }
    let nonce = &data[..24];
    let ciphertext = &data[24..];
    let key = load_key_from_file()?;
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    fs::write(output_path, plaintext)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect command-line arguments.
    let args: Vec<String> = env::args().collect();

    // Expect exactly 4 arguments: program, flag, input, output.
    if args.len() != 4 {
        eprintln!("Error: expected usage: {} [-E|-D] <input> <output>", args[0]);
        std::process::exit(1);
    }

    let flag = &args[1];
    let input = &args[2];
    let output = &args[3];

    match flag.as_str() {
        "-E" => encrypt_file(input, output)?,
        "-D" => decrypt_file(input, output)?,
        _ => {
            eprintln!("Error: Unknown flag {}. Use -E for encryption or -D for decryption.", flag);
            std::process::exit(1);
        }
    }

    Ok(())
}


