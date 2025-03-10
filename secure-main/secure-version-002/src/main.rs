use std::{env, fs};
use std::io::{self, Write};
use rand::RngCore;
use sha2::{Sha256, Digest};

fn xor_data(input: &[u8], key: &[u8]) -> Vec<u8> {
    input.iter()
         .zip(key.iter().cycle())
         .map(|(&b, &k)| b ^ k)
         .collect()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: stdotp <E|D> <input_file> <output_file>");
        std::process::exit(1);
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];

    // Load keys from files
    let key_primary = fs::read("key.key")?;
    let key_secondary = fs::read("key1.key")?;

    let input_data = fs::read(input_file)?;

    if mode == "E" {
        // Layer 1 encryption (key.key + nonce_layer1)
        let mut nonce_layer1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_layer1);

        let derived_key_layer1: Vec<u8> = nonce_layer1.iter()
            .enumerate()
            .map(|(i, &nonce_byte)| nonce_byte ^ key_primary[i % key_primary.len()])
            .collect();

        let intermediate_ciphertext = xor_data(&input_data, &derived_key_layer1);

        // Layer 2 encryption (key1.key + nonce_layer2)
        let mut nonce_layer2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_layer2);

        let derived_key_layer2: Vec<u8> = nonce_layer2.iter()
            .enumerate()
            .map(|(i, &nonce_byte)| nonce_byte ^ key_secondary[i % key_secondary.len()])
            .collect();

        let final_ciphertext = xor_data(&intermediate_ciphertext, &derived_key_layer2);

        // Authentication hash (SHA-256)
        let mut hasher = Sha256::new();
        hasher.update(&final_ciphertext);
        let auth_hash = hasher.finalize();

        // Write file: nonce1 | nonce2 | hash | ciphertext
        let mut output = fs::File::create(output_file)?;
        output.write_all(&nonce_layer1)?;
        output.write_all(&nonce_layer2)?;
        output.write_all(&auth_hash)?;
        output.write_all(&final_ciphertext)?;

        println!("Encryption successful.");

    } else { // Decrypt
        if input_data.len() < 96 {
            eprintln!("Error: Encrypted file too short.");
            std::process::exit(1);
        }

        // Read file: nonce1(32) | nonce2(32) | hash(32) | ciphertext
        let (nonce_layer1, rest) = input_data.split_at(32);
        let (nonce_layer2, rest) = rest.split_at(32);
        let (stored_hash, ciphertext) = rest.split_at(32);

        // Verify authentication hash first
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        let calculated_hash = hasher.finalize();

        if stored_hash != calculated_hash.as_slice() {
            eprintln!("Error: Authentication failed! File may have been tampered with.");
            std::process::exit(1);
        }

        // Layer 2 Decryption
        let derived_key_layer2: Vec<u8> = nonce_layer2.iter()
            .enumerate()
            .map(|(i, &nonce_byte)| nonce_byte ^ key_secondary[i % key_secondary.len()])
            .collect();

        let intermediate_plaintext = xor_data(ciphertext, &derived_key_layer2);

        // Layer 1 Decryption
        let derived_key_layer1: Vec<u8> = nonce_layer1.iter()
            .enumerate()
            .map(|(i, &nonce_byte)| nonce_byte ^ key_primary[i % key_primary.len()])
            .collect();

        let final_plaintext = xor_data(&intermediate_plaintext, &derived_key_layer1);

        fs::write(output_file, final_plaintext)?;

        println!("Decryption and authentication successful.");
    }

    Ok(())
}

