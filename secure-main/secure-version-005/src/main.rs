
use std::{env, fs, process, io::{self, Write}};
use rand::RngCore;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use argon2::Argon2;

type HmacSha256 = Hmac<Sha256>;

/// Generates a pseudorandom keystream of the specified length using a counter‑mode HMAC construction.
fn generate_keystream(enc_key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length);
    let mut counter = 0u64;
    while keystream.len() < length {
        let mut data = Vec::with_capacity(nonce.len() + 8);
        data.extend_from_slice(nonce);
        data.extend_from_slice(&counter.to_le_bytes());
        let mut mac = HmacSha256::new_from_slice(enc_key)
            .expect("HMAC can take key of any size");
        mac.update(&data);
        let block = mac.finalize().into_bytes();
        keystream.extend_from_slice(&block);
        counter += 1;
    }
    keystream.truncate(length);
    keystream
}

/// XORs the input data with the provided keystream.
fn xor_data(data: &[u8], keystream: &[u8]) -> Vec<u8> {
    data.iter().zip(keystream.iter()).map(|(&a, &b)| a ^ b).collect()
}

/// Derives a 32-byte key using Argon2 with the given password and salt.
fn derive_key_argon2(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 key derivation failed");
    key
}

/// Reads a key from the specified file and ensures it is exactly 32 bytes.
fn read_key_from_file(filename: &str) -> io::Result<Vec<u8>> {
    let key = fs::read(filename)?;
    if key.len() != 32 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Key file {} must be exactly 32 bytes", filename),
        ))
    } else {
        Ok(key)
    }
}

fn main() -> io::Result<()> {
    // Expected usage:
    // For file mode (keys from files): <E|D> <input_file> <output_file>
    // For password mode: <E|D> <input_file> <output_file> <password>
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 && args.len() != 5 {
        eprintln!("Usage: <E|D> <input_file> <output_file> [optional password]");
        process::exit(1);
    }
    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];
    let use_password = args.len() == 5;
    let password = if use_password { Some(&args[4]) } else { None };

    let data = fs::read(input_file)?;

    if mode == "E" {
        if use_password {
            // Password mode encryption:
            // Generate nonce (32 bytes) and two random salts (16 bytes each)
            let mut nonce = [0u8; 32];
            let mut salt1 = [0u8; 16];
            let mut salt2 = [0u8; 16];
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut salt1);
            rng.fill_bytes(&mut salt2);

            // Derive keys using Argon2.
            let enc_key = derive_key_argon2(password.unwrap(), &salt1);
            let mac_key = derive_key_argon2(password.unwrap(), &salt2);

            // Encrypt data.
            let keystream = generate_keystream(&enc_key, &nonce, data.len());
            let ciphertext = xor_data(&data, &keystream);

            // Compute HMAC over nonce || ciphertext.
            let mut mac = HmacSha256::new_from_slice(&mac_key)
                .expect("HMAC can take key of any size");
            mac.update(&nonce);
            mac.update(&ciphertext);
            let auth_tag = mac.finalize().into_bytes();

            // File format for password mode:
            // [Header (1 byte)=1] || nonce (32 bytes) || salt1 (16 bytes) || salt2 (16 bytes) || auth tag (32 bytes) || ciphertext
            let mut output = fs::File::create(output_file)?;
            output.write_all(&[1u8])?;
            output.write_all(&nonce)?;
            output.write_all(&salt1)?;
            output.write_all(&salt2)?;
            output.write_all(&auth_tag)?;
            output.write_all(&ciphertext)?;

            println!("Encryption (password mode) successful.");
        } else {
            // File mode encryption:
            // Read keys from "1.key" and "2.key"
            let enc_key = read_key_from_file("1.key")?;
            let mac_key = read_key_from_file("2.key")?;

            // Generate nonce.
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Encrypt data.
            let keystream = generate_keystream(&enc_key, &nonce, data.len());
            let ciphertext = xor_data(&data, &keystream);

            // Compute HMAC over nonce || ciphertext.
            let mut mac = HmacSha256::new_from_slice(&mac_key)
                .expect("HMAC can take key of any size");
            mac.update(&nonce);
            mac.update(&ciphertext);
            let auth_tag = mac.finalize().into_bytes();

            // File format for file mode:
            // [Header (1 byte)=0] || nonce (32 bytes) || auth tag (32 bytes) || ciphertext
            let mut output = fs::File::create(output_file)?;
            output.write_all(&[0u8])?;
            output.write_all(&nonce)?;
            output.write_all(&auth_tag)?;
            output.write_all(&ciphertext)?;

            println!("Encryption (file mode) successful.");
        }
    } else if mode == "D" {
        if data.len() < 1 {
            eprintln!("Error: Encrypted file too short.");
            process::exit(1);
        }
        // Read the header byte to determine the mode used during encryption.
        let mode_flag = data[0];
        if mode_flag == 1 {
            // Password mode decryption:
            // Expected file layout:
            // Header (1) || nonce (32) || salt1 (16) || salt2 (16) || auth tag (32) || ciphertext
            if !use_password {
                eprintln!("Error: Password is required for decrypting this file.");
                process::exit(1);
            }
            if data.len() < 1 + 32 + 16 + 16 + 32 {
                eprintln!("Error: Encrypted file too short for password mode.");
                process::exit(1);
            }
            let nonce = &data[1..33];
            let salt1 = &data[33..49];
            let salt2 = &data[49..65];
            let stored_auth_tag = &data[65..97];
            let ciphertext = &data[97..];

            // Derive keys using Argon2.
            let enc_key = derive_key_argon2(password.unwrap(), salt1);
            let mac_key = derive_key_argon2(password.unwrap(), salt2);

            // Verify authentication tag.
            let mut mac = HmacSha256::new_from_slice(&mac_key)
                .expect("HMAC can take key of any size");
            mac.update(nonce);
            mac.update(ciphertext);
            if mac.verify_slice(stored_auth_tag).is_err() {
                eprintln!("Error: Authentication failed! File may have been tampered with.");
                process::exit(1);
            }

            // Decrypt data.
            let keystream = generate_keystream(&enc_key, nonce, ciphertext.len());
            let plaintext = xor_data(ciphertext, &keystream);

            fs::write(output_file, plaintext)?;
            println!("Decryption (password mode) successful.");
        } else if mode_flag == 0 {
            // File mode decryption:
            // Expected file layout:
            // Header (1) || nonce (32) || auth tag (32) || ciphertext
            if use_password {
                eprintln!("Error: No password should be provided for decrypting this file (file mode).");
                process::exit(1);
            }
            if data.len() < 1 + 32 + 32 {
                eprintln!("Error: Encrypted file too short for file mode.");
                process::exit(1);
            }
            let nonce = &data[1..33];
            let stored_auth_tag = &data[33..65];
            let ciphertext = &data[65..];

            // Read keys from files.
            let enc_key = read_key_from_file("1.key")?;
            let mac_key = read_key_from_file("2.key")?;

            // Verify authentication tag.
            let mut mac = HmacSha256::new_from_slice(&mac_key)
                .expect("HMAC can take key of any size");
            mac.update(nonce);
            mac.update(ciphertext);
            if mac.verify_slice(stored_auth_tag).is_err() {
                eprintln!("Error: Authentication failed! File may have been tampered with.");
                process::exit(1);
            }

            // Decrypt data.
            let keystream = generate_keystream(&enc_key, nonce, ciphertext.len());
            let plaintext = xor_data(ciphertext, &keystream);

            fs::write(output_file, plaintext)?;
            println!("Decryption (file mode) successful.");
        } else {
            eprintln!("Error: Unknown file header mode.");
            process::exit(1);
        }
    } else {
        eprintln!("Invalid mode: use E for encryption or D for decryption.");
        process::exit(1);
    }

    Ok(())
}

