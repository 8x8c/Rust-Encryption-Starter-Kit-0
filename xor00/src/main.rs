use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

fn main() {
    // -------------------------------------------------------------
    // Settings: Modify SALT here to change the base for key derivation
    // -------------------------------------------------------------
    const SALT: &[u8] = b"MY_SALT_FOR_XOR_KEY"; 
    // -------------------------------------------------------------

    // 1) Ask the user for the file name
    println!("Enter the file name to encrypt:");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line from stdin");
    let filename = input.trim();

    // 2) Ask the user for a password
    println!("Enter the password:");
    let mut pwd_input = String::new();
    io::stdin()
        .read_line(&mut pwd_input)
        .expect("Failed to read password from stdin");
    let password = pwd_input.trim();

    // 3) Read the file contents into a buffer
    let mut file = File::open(filename).expect("Failed to open input file");
    let mut file_buffer = Vec::new();
    file.read_to_end(&mut file_buffer)
        .expect("Failed to read file contents");

    // 4) Create the combined key material: SALT + password
    let mut key_material = Vec::with_capacity(SALT.len() + password.len());
    key_material.extend_from_slice(SALT);
    key_material.extend_from_slice(password.as_bytes());

    // 5) Repeat the combined key to match the length of the file buffer
    let mut key_buffer = Vec::with_capacity(file_buffer.len());
    for i in 0..file_buffer.len() {
        // Use each byte in `key_material` in a repeating cycle
        key_buffer.push(key_material[i % key_material.len()]);
    }

    // 6) XOR each byte in the file buffer with the corresponding byte in the key
    for (file_byte, key_byte) in file_buffer.iter_mut().zip(key_buffer.iter()) {
        *file_byte ^= *key_byte;
    }

    // 7) Write the encrypted contents to a new file: <filename>.enc
    let output_filename = format!("{}.enc", filename);
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&output_filename)
        .expect("Failed to create output file");
    
    output_file
        .write_all(&file_buffer)
        .expect("Failed to write encrypted file");

    println!("Encryption finished! Encrypted file: {}", output_filename);
}
