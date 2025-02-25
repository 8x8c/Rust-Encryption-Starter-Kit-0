use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

fn main() {
    // 1) Ask the user for the file name
    println!("Enter the file name to encrypt/decrypt in-place:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read file name");
    let filename = input.trim();

    // 2) Ask the user for the password
    println!("Enter your password:");
    let mut pwd_input = String::new();
    io::stdin().read_line(&mut pwd_input).expect("Failed to read password");
    let password = pwd_input.trim();

    // 3) Read the file contents into a buffer
    let mut file = File::open(filename).expect("Failed to open file");
    let mut file_buffer = Vec::new();
    file.read_to_end(&mut file_buffer).expect("Failed to read file");

    // 4) Generate the key by expanding the password to match the file size
    let key_buffer = expand_key(password, file_buffer.len());

    // 5) XOR each byte of the file buffer with the corresponding byte of the key
    for (byte, key) in file_buffer.iter_mut().zip(key_buffer.iter()) {
        *byte ^= *key;
    }

    // 6) Overwrite the original file with the XORed data
    let mut output_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(filename)
        .expect("Failed to open file for writing");

    output_file
        .write_all(&file_buffer)
        .expect("Failed to write XORed data to file");

    println!("Done! The file has been overwritten in-place.");
    println!("Use the **same password** again on this file to decrypt it.");
}

/// Expand the user’s password into a key of `length` bytes by hashing 
/// repeatedly with a counter. This helps avoid obvious repetition 
/// if the file is larger than 32 bytes. 
/// For a secure system, use a proper KDF (PBKDF2, Argon2, etc.).
fn expand_key(password: &str, length: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(length);
    let mut block_count = 0u64;

    while key.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(block_count.to_le_bytes()); 
        let hash_output = hasher.finalize_reset();
        key.extend_from_slice(&hash_output);
        block_count += 1;
    }

    key.truncate(length);
    key
}
