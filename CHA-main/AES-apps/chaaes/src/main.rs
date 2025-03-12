use std::fs;
use std::io::{Read, Write};
use clap::{Arg, Command};
use rand::RngCore;
use aes_gcm::aead::{Aead, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Argon2, Params, Algorithm, Version};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("CHAAES")
        .version("1.0")
        .about("Encrypts and decrypts files securely using AES-256-GCM and Argon2id")
        .subcommand_required(true)
        .subcommand(
            Command::new("encrypt")
                .about("Encrypts a file")
                .arg(Arg::new("input")
                     .short('i')
                     .long("input")
                     .required(true)
                     .num_args(1)
                     .help("Path to the input file"))
                .arg(Arg::new("output")
                     .short('o')
                     .long("output")
                     .required(true)
                     .num_args(1)
                     .help("Path to the output (encrypted) file"))
                .arg(Arg::new("password")
                     .short('p')
                     .long("password")
                     .required(true)
                     .num_args(1)
                     .help("Password for encryption"))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a file")
                .arg(Arg::new("input")
                     .short('i')
                     .long("input")
                     .required(true)
                     .num_args(1)
                     .help("Path to the input (encrypted) file"))
                .arg(Arg::new("output")
                     .short('o')
                     .long("output")
                     .required(true)
                     .num_args(1)
                     .help("Path to the output (decrypted) file"))
                .arg(Arg::new("password")
                     .short('p')
                     .long("password")
                     .required(true)
                     .num_args(1)
                     .help("Password for decryption"))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_m)) => {
            let input_path = sub_m.get_one::<String>("input").unwrap();
            let output_path = sub_m.get_one::<String>("output").unwrap();
            let password = sub_m.get_one::<String>("password").unwrap();

            // Read the entire input file into memory.
            let plaintext = fs::read(input_path)?;

            // Generate random salt and nonce.
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Configure Argon2id parameters.
            let params = Params::new(65536, 3, 4, Some(32))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Argon2 parameter error: {}", e)))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            // Derive a 32-byte key from the password and salt.
            let mut key = [0u8; 32];
            argon2.hash_password_into(password.as_bytes(), &salt, &mut key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Argon2 hash error: {}", e)))?;
            let key = GenericArray::clone_from_slice(&key);

            // Encrypt using AES-256-GCM (provides confidentiality and integrity).
            let cipher = Aes256Gcm::new(&key);
            let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
                .map_err(|_| "Encryption failed")?;

            // Write output file: magic header, salt, nonce, then ciphertext.
            let mut out_file = fs::File::create(output_path)?;
            out_file.write_all(b"SECUREENC")?;  // 9-byte magic header
            out_file.write_all(&salt)?;
            out_file.write_all(&nonce)?;
            out_file.write_all(&ciphertext)?;
        },
        Some(("decrypt", sub_m)) => {
            let input_path = sub_m.get_one::<String>("input").unwrap();
            let output_path = sub_m.get_one::<String>("output").unwrap();
            let password = sub_m.get_one::<String>("password").unwrap();

            // Open the encrypted file.
            let mut file = fs::File::open(input_path)?;
            let mut header = [0u8; 9];
            file.read_exact(&mut header)?;
            if &header != b"SECUREENC" {
                return Err("Invalid file header. This file may not be encrypted with this tool.".into());
            }

            // Read salt and nonce from the file.
            let mut salt = [0u8; 16];
            file.read_exact(&mut salt)?;
            let mut nonce = [0u8; 12];
            file.read_exact(&mut nonce)?;
            let mut ciphertext = Vec::new();
            file.read_to_end(&mut ciphertext)?;

            // Recreate Argon2id configuration to derive the same key.
            let params = Params::new(65536, 3, 4, Some(32))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Argon2 parameter error: {}", e)))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut key = [0u8; 32];
            argon2.hash_password_into(password.as_bytes(), &salt, &mut key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Argon2 hash error: {}", e)))?;
            let key = GenericArray::clone_from_slice(&key);
            let cipher = Aes256Gcm::new(&key);

            // Attempt decryption. If authentication fails, an error will be returned.
            let plaintext = cipher.decrypt(GenericArray::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| "Decryption failed. Incorrect password or data is corrupted.")?;
            fs::write(output_path, plaintext)?;
        },
        _ => unreachable!(),
    }

    Ok(())
}


