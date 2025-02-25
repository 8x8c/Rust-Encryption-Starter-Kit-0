// A Creative (but NOT secure) CLI Encryption App in Rust (Standard Library Only)
//
// This example implements a toy encryption scheme that simply XORs
// each byte of the file with a byte from a simple pseudorandom stream.
// The PRNG is seeded with a simple FNV-1a hash of the provided password.
// This is just for demonstration purposes – it is NOT secure, nor is it
// post-quantum secure. Implementing modern (post-quantum) crypto correctly
// requires extensive code and vetted algorithms, usually available via crates.
//
// The program reads a file, “encrypts” (or decrypts) its content in memory,
// writes the output to a temporary file, and finally atomically renames the
// temporary file over the original file. This minimizes the risk of data loss.

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};

/// A simple XORShift PRNG.
struct SimpleRNG {
    state: u64,
}

impl SimpleRNG {
    fn new(seed: u64) -> Self {
        SimpleRNG { state: seed }
    }

    /// Generate the next 32-bit pseudorandom number.
    fn next(&mut self) -> u32 {
        // A simple XORShift algorithm (not cryptographically secure).
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state & 0xFFFF_FFFF) as u32
    }
}

/// Derive a simple seed from the password using FNV-1a.
fn derive_seed(password: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for b in password.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    }
    hash
}

/// Process the file: read its content, encrypt/decrypt it, and atomically replace it.
fn process_file(path: &str, password: &str) -> io::Result<()> {
    // Read the original file
    let data = fs::read(path)?;
    
    // Create a PRNG seeded with a hash of the password.
    let seed = derive_seed(password);
    let mut rng = SimpleRNG::new(seed);
    
    // Process the data: XOR each byte with a pseudorandom byte.
    // (Encryption and decryption are identical in an XOR cipher.)
    let processed: Vec<u8> = data
        .into_iter()
        .map(|byte| {
            let rand_byte = (rng.next() % 256) as u8;
            byte ^ rand_byte
        })
        .collect();

    // Write the output to a temporary file in the same directory.
    let temp_path = format!("{}.tmp", path);
    {
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(&processed)?;
        // Flush data to disk.
        temp_file.sync_all()?;
    }
    
    // Atomically replace the original file with the temporary file.
    fs::rename(temp_path, path)?;
    
    Ok(())
}

/// Print usage instructions.
fn print_usage(program: &str) {
    eprintln!("Usage: {} <file> <password>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        print_usage(&args[0]);
        return;
    }
    
    let file_path = &args[1];
    let password = &args[2];

    match process_file(file_path, password) {
        Ok(()) => println!("File processed successfully."),
        Err(e) => eprintln!("Error processing file: {}", e),
    }
}
