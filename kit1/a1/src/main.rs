use std::{env, fs};
use std::io::{self, Write};

fn main() -> io::Result<()> {
    // Retrieve command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: a1 <input_filename> <output_filename>");
        std::process::exit(1);
    }

    let input_file_path = &args[1];
    let output_file_path = &args[2];
    let key_path = "key.key";

    // Read the input file
    let input_data = fs::read(input_file_path).map_err(|e| {
        eprintln!("Error reading input file '{}': {}", input_file_path, e);
        e
    })?;

    // Read the key file
    let key_data = fs::read(key_path).map_err(|e| {
        eprintln!("Error reading key file '{}': {}", key_path, e);
        e
    })?;

    if key_data.is_empty() {
        eprintln!("Error: Key file '{}' is empty.", key_path);
        std::process::exit(1);
    }

    // Ensure the key is at least as large as the input file
    if key_data.len() < input_data.len() {
        eprintln!("Error: Key file '{}' must be as large as the input file or larger.", key_path);
        std::process::exit(1);
    }

    // XOR encryption/decryption without key wrapping
    let xor_result: Vec<u8> = input_data
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_data[i])
        .collect();

    // Write the output file
    let mut output_file = fs::File::create(output_file_path).map_err(|e| {
        eprintln!("Error creating output file '{}': {}", output_file_path, e);
        e
    })?;

    output_file.write_all(&xor_result).map_err(|e| {
        eprintln!("Error writing to output file '{}': {}", output_file_path, e);
        e
    })?;

    Ok(())
}

