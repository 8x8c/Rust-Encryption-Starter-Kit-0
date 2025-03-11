// [dependencies]
// rand = "0.8"
// sha2 = "0.10"
// hmac = "0.12"
// argon2 = { version = "0.5", features = ["password-hash"] }

use std::{env, fs};
use std::io::{self, Write};
use rand::RngCore;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

type HmacSha256 = Hmac<Sha256>;

fn xor_data(input: &[u8], key: &[u8]) -> Vec<u8> {
    input.iter().zip(key.iter()).map(|(&b, &k)| b ^ k).collect()
}

fn derive_auth_key(key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(nonce).expect("Failed to create salt");
    let hash = argon2.hash_password(key, &salt).expect("KDF failed");
    hash.hash.expect("No hash output").as_bytes().to_vec()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: xorotp <E|D> <input_file> <output_file>");
        std::process::exit(1);
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];

    let key_primary = fs::read("key.key")?;
    let key_secondary = fs::read("key1.key")?;
    let input_data = fs::read(input_file)?;

    if mode == "E" {
        if key_primary.len() < input_data.len() || key_secondary.len() < input_data.len() {
            eprintln!("Error: Keys must be at least as long as the plaintext file.");
            std::process::exit(1);
        }

        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let intermediate = xor_data(&input_data, &key_primary[..input_data.len()]);
        let final_ciphertext = xor_data(&intermediate, &key_secondary[..input_data.len()]);

        let auth_key = derive_auth_key(&key_secondary[input_data.len()..], &nonce);
        let mut mac = HmacSha256::new_from_slice(&auth_key).expect("HMAC init failed");
        mac.update(&nonce);
        mac.update(&final_ciphertext);
        let auth_tag = mac.finalize().into_bytes();

        let plaintext_length = (input_data.len() as u64).to_le_bytes();

        let mut output = fs::File::create(output_file)?;
        output.write_all(&nonce)?;
        output.write_all(&auth_tag)?;
        output.write_all(&plaintext_length)?;
        output.write_all(&final_ciphertext)?;

        println!("Encryption successful.");

    } else {
        if input_data.len() < 72 {
            eprintln!("Encrypted file too short.");
            std::process::exit(1);
        }

        let (nonce, rest) = input_data.split_at(32);
        let (stored_auth_tag, rest) = rest.split_at(32);
        let (plaintext_length_bytes, ciphertext) = rest.split_at(8);

        let plaintext_len = u64::from_le_bytes(plaintext_length_bytes.try_into().unwrap()) as usize;

        if key_primary.len() < plaintext_len || key_secondary.len() < plaintext_len {
            eprintln!("Error: Keys are too short for decrypted plaintext length.");
            std::process::exit(1);
        }

        let auth_key = derive_auth_key(&key_secondary[plaintext_len..], nonce);
        let mut mac = HmacSha256::new_from_slice(&auth_key).expect("HMAC init failed");
        mac.update(nonce);
        mac.update(ciphertext);

        if mac.verify_slice(stored_auth_tag).is_err() {
            eprintln!("Authentication failed! File tampered.");
            std::process::exit(1);
        }

        let intermediate = xor_data(ciphertext, &key_secondary[..plaintext_len]);
        let final_plaintext = xor_data(&intermediate, &key_primary[..plaintext_len]);

        fs::write(output_file, final_plaintext)?;
        println!("Decryption and authentication successful.");
    }

    Ok(())
}


