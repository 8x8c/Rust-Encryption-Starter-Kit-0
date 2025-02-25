use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

fn main() {
    // -------------------------------------------------------------
    // Settings: Modify SALT here to change the deterministic key
    // -------------------------------------------------------------
    const SALT: &[u8] = b"MY_SALT_FOR_XOR_KEY"; 
    // -------------------------------------------------------------

    // Prompt user for the file name
    println!("Enter the file name to encrypt:");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line from stdin");

    // Trim to remove any trailing newline characters
    let filename = input.trim();

    // Read the contents of the file
    let mut file = File::open(filename).expect("Failed to open input file");
    let mut file_buffer = Vec::new();
    file.read_to_end(&mut file_buffer)
        .expect("Failed to read file contents");

    // Generate a deterministic key based on the length of the file
    // We'll simply repeat the SALT until it's the same length as file_buffer.
    let mut key_buffer = Vec::with_capacity(file_buffer.len());
    for i in 0..file_buffer.len() {
        key_buffer.push(SALT[i % SALT.len()]);
    }

    // XOR each byte in the file buffer with the corresponding byte in the key
    for (file_byte, key_byte) in file_buffer.iter_mut().zip(key_buffer.iter()) {
        *file_byte ^= *key_byte;
    }

    // Write the encrypted contents to a new file (filename.enc)
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
