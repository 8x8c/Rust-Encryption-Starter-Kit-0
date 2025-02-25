use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

fn main() {
    // 1) Get the file name
    println!("Enter the file name to encrypt/decrypt in-place:");
    let mut input_filename = String::new();
    io::stdin()
        .read_line(&mut input_filename)
        .expect("Failed to read file name");
    let filename = input_filename.trim();

    // 2) Get the password (entire password is used as key)
    println!("Enter your password (entire password is the key):");
    let mut password_input = String::new();
    io::stdin()
        .read_line(&mut password_input)
        .expect("Failed to read password");
    let password = password_input.trim(); // Trim whitespace/newline

    // 3) Read the file into a buffer
    let mut file = File::open(filename).expect("Failed to open file");
    let mut file_buffer = Vec::new();
    file.read_to_end(&mut file_buffer)
        .expect("Failed to read file contents");

    // 4) Generate the XOR key by repeating (or truncating) the password
    let password_bytes = password.as_bytes();
    let file_size = file_buffer.len();

    let mut key_buffer = Vec::with_capacity(file_size);
    for i in 0..file_size {
        key_buffer.push(password_bytes[i % password_bytes.len()]);
    }

    // 5) XOR the file buffer in-place
    for (file_byte, key_byte) in file_buffer.iter_mut().zip(key_buffer.iter()) {
        *file_byte ^= *key_byte;
    }

    // 6) Overwrite the original file
    let mut output_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(filename)
        .expect("Failed to open file for writing");
    output_file
        .write_all(&file_buffer)
        .expect("Failed to write XORed data to file");

    println!("Done! The file has been overwritten in-place.");
    println!("Use the SAME password again on this file to revert it.");
}
