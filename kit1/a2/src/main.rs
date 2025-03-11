use std::{env, fs};
use std::io::{self, Write};
use rand::Rng;

fn main() -> io::Result<()> {
    // Expect mode ("E" or "D"), input filename, and output filename
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: xor <E|D> <input_filename> <output_filename>");
        std::process::exit(1);
    }
    let mode = &args[1];
    let input_file_path = &args[2];
    let output_file_path = &args[3];
    let key_path = "key.key";

    // Read the key file
    let key_data = fs::read(key_path).map_err(|e| {
        eprintln!("Error reading key file '{}': {}", key_path, e);
        e
    })?;

    if key_data.is_empty() {
        eprintln!("Error: Key file '{}' is empty.", key_path);
        std::process::exit(1);
    }

    if mode == "E" {
        // Read the plaintext input file
        let plaintext = fs::read(input_file_path).map_err(|e| {
            eprintln!("Error reading input file '{}': {}", input_file_path, e);
            e
        })?;

        // Ensure the key is large enough
        if key_data.len() < plaintext.len() {
            eprintln!("Error: Key file '{}' must be as large as the input file.", key_path);
            std::process::exit(1);
        }

        // Generate a random nonce as long as the plaintext
        let mut rng = rand::thread_rng();
        let nonce: Vec<u8> = (0..plaintext.len()).map(|_| rng.r#gen()).collect();

        // Compute the effective pad: key XOR nonce
        let pad: Vec<u8> = nonce.iter().enumerate()
            .map(|(i, &nonce_byte)| key_data[i] ^ nonce_byte)
            .collect();

        // Encrypt: ciphertext = plaintext XOR pad
        let ciphertext: Vec<u8> = plaintext.iter().enumerate()
            .map(|(i, &pt_byte)| pt_byte ^ pad[i])
            .collect();

        // Write the output file with nonce prepended to ciphertext
        let mut output_file = fs::File::create(output_file_path).map_err(|e| {
            eprintln!("Error creating output file '{}': {}", output_file_path, e);
            e
        })?;
        output_file.write_all(&nonce)?;
        output_file.write_all(&ciphertext)?;
    } else if mode == "D" {
        // Read the encrypted file (which should contain nonce + ciphertext)
        let encrypted_data = fs::read(input_file_path).map_err(|e| {
            eprintln!("Error reading input file '{}': {}", input_file_path, e);
            e
        })?;

        // Expect the encrypted file to have nonce and ciphertext of equal lengths.
        if encrypted_data.len() % 2 != 0 {
            eprintln!("Error: Encrypted file length is not even, so it cannot be split into nonce and ciphertext.");
            std::process::exit(1);
        }
        let half = encrypted_data.len() / 2;
        let (nonce, ciphertext) = encrypted_data.split_at(half);

        if key_data.len() < nonce.len() {
            eprintln!("Error: Key file '{}' must be as large as the plaintext (nonce length).", key_path);
            std::process::exit(1);
        }

        // Compute the effective pad: key XOR nonce
        let pad: Vec<u8> = nonce.iter().enumerate()
            .map(|(i, &nonce_byte)| key_data[i] ^ nonce_byte)
            .collect();

        // Decrypt: plaintext = ciphertext XOR pad
        let plaintext: Vec<u8> = ciphertext.iter().enumerate()
            .map(|(i, &ct_byte)| ct_byte ^ pad[i])
            .collect();

        // Write the plaintext to the output file
        let mut output_file = fs::File::create(output_file_path).map_err(|e| {
            eprintln!("Error creating output file '{}': {}", output_file_path, e);
            e
        })?;
        output_file.write_all(&plaintext)?;
    } else {
        eprintln!("Invalid mode: {}. Use 'E' for encryption or 'D' for decryption.", mode);
        std::process::exit(1);
    }

    Ok(())
}


