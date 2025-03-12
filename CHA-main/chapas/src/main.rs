
use std::env;
use std::fs;
use std::io;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use argon2::Argon2;
use rpassword::prompt_password;

/// Derives a 32‑byte key from the provided password and salt using Argon2.
fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
          .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(key)
}

/// Encrypts the file at `input_path` and writes the result to `output_path`.
/// Output format: [salt (16 bytes)] || [nonce (24 bytes)] || [ciphertext]
fn encrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input_path)?;
    
    // Ask for password twice to verify it.
    let password1 = prompt_password("Enter password: ")?;
    let password2 = prompt_password("Re-enter password: ")?;
    if password1 != password2 {
        eprintln!("Error: Passwords do not match.");
        std::process::exit(1);
    }
    let password = password1;
    
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key_from_password(&password, &salt)?;
    
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    
    let mut output = salt.to_vec();
    output.extend(&nonce);
    output.extend(ciphertext);
    fs::write(output_path, output)?;
    Ok(())
}

/// Decrypts the file at `input_path` and writes the plaintext to `output_path`.
/// Expects file format: [salt (16 bytes)] || [nonce (24 bytes)] || [ciphertext]
fn decrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    if data.len() < 16 + 24 {
        return Err("Input file too short to contain a valid salt and nonce.".into());
    }
    let salt = &data[..16];
    let nonce = &data[16..16+24];
    let ciphertext = &data[16+24..];
    
    let password = prompt_password("Enter password: ")?;
    let key = derive_key_from_password(&password, salt)?;
    
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    fs::write(output_path, plaintext)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            eprintln!("Error: unknown flag {}. Use -E for encryption or -D for decryption.", flag);
            std::process::exit(1);
        }
    }

    Ok(())
}

