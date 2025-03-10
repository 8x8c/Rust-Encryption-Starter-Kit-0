use std::{env, fs};
use std::io::{self, Write};
use rand::RngCore;
use sha2::{Sha256, Digest};

fn xor_data(input: &[u8], key: &[u8]) -> Vec<u8> {
    input.iter().zip(key.iter().cycle()).map(|(&b, &k)| b ^ k).collect()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: secure <E|D> <input_filename> <output_filename>");
        std::process::exit(1);
    }

    let mode = &args[1];
    let input_file_path = &args[2];
    let output_file_path = &args[3];
    let key_path = "key.key";

    let input_data = fs::read(input_file_path)?;
    let key_data = fs::read(key_path)?;

    if mode == "E" {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let derived_key: Vec<u8> = nonce.iter()
            .enumerate()
            .map(|(i, &n)| key_data[i % key_data.len()] ^ n)
            .chain(key_data.iter().cycle().skip(nonce.len()).take(input_data.len() - nonce.len()).cloned())
            .collect();

        let intermediate_cipher = xor_data(&input_data, &derived_key);

        let mut second_nonce = vec![0u8; intermediate_cipher.len()];
        rand::thread_rng().fill_bytes(&mut second_nonce);

        let final_cipher_text = xor_data(&intermediate_cipher, &second_nonce);

        let mut hasher = Sha256::new();
        hasher.update(&final_cipher_text);
        let hash = hasher.finalize();

        let mut output_file = fs::File::create(output_file_path)?;
        output_file.write_all(&nonce)?;
        output_file.write_all(&second_nonce)?;
        output_file.write_all(&hash)?;
        output_file.write_all(&final_cipher_text)?;

        println!("Encryption successful.");
    } else {
        if input_data.len() < 96 {
            eprintln!("Error: Encrypted file is too short.");
            std::process::exit(1);
        }

        let nonce_size = 32;
        let hash_size = 32;

        let (nonce, rest) = input_data.split_at(nonce_size);
        let (second_nonce, rest) = rest.split_at(rest.len() - hash_size - (input_data.len() - nonce_size - hash_size) / 2);
        let (stored_hash, final_cipher_text) = rest.split_at(hash_size);

        let mut hasher = Sha256::new();
        hasher.update(&final_cipher_text);
        let computed_hash = hasher.finalize();

        if computed_hash.as_slice() != stored_hash {
            eprintln!("Error: Authentication failed. The file may have been tampered with.");
            std::process::exit(1);
        }

        let intermediate_cipher = xor_data(&final_cipher_text, &second_nonce);

        let derived_key: Vec<u8> = nonce.iter()
            .enumerate()
            .map(|(i, &n)| key_data[i % key_data.len()] ^ n)
            .chain(key_data.iter().cycle().skip(nonce.len()).take(intermediate_cipher.len() - nonce.len()).cloned())
            .collect();

        let plain_text = xor_data(&intermediate_cipher, &derived_key);

        fs::write(output_file_path, plain_text)?;
        println!("Decryption and authentication successful.");
    }

    Ok(())
}



