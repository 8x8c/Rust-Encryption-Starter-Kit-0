
// [dependencies]
// argon2 = "0.5.3"
// rand_chacha = "0.9.0"
// rand_core = "0.9.0"








use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::exit;

use argon2::{Argon2, Params, Version, Algorithm};


use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

//
// Compile‑time constants: adjust these to change parameters without modifying core logic
//

// --- Key Generation Options ---
//
// Maximum key size allowed (in bytes). Here up to 5GB is permitted.
const MAX_SIZE: u64 = 5 * 1024 * 1024 * 1024; 

// Chunk size for writing out key bytes. Using chunks prevents excessive memory use when generating large keys.
const CHUNK_SIZE: usize = 64 * 1024; 

// Salt for the key derivation function (KDF).  
// Using a fixed salt ensures that the process is deterministic.
// Changing the salt will completely alter the derived keys.
const KDF_SALT: &str = "DeterministicKeySalt_v1";

// Maximum allowed password length (in bytes).  
// This limits the input to avoid abuse (e.g., denial-of-service from extremely long passwords).
const MAX_PASSWORD_LENGTH: usize = 1024; 

// --- Argon2 Parameter Options ---
//
// These parameters configure the Argon2 key derivation function.
// They control the computational and memory cost, which are crucial for security.
//
// Memory cost (in KiB): Determines how much memory Argon2 will use.  
// A higher memory cost increases resistance to GPU-based attacks.  
// Here, 65536 KiB equals 64 MiB.
const ARGON2_MEMORY_COST: u32 = 65536; 

// Iteration count (or time cost): Number of passes over the memory.  
// More iterations increase computational time, making brute-force attacks more expensive.
const ARGON2_ITERATIONS: u32 = 3; 

// Parallelism (number of lanes): The number of threads Argon2 uses.  
// Typically, 1 is acceptable for single-threaded usage, but it can be increased if desired.
const ARGON2_PARALLELISM: u32 = 1; 

// --- Acceptable Ranges for Argon2 Parameters ---
//
// These constants define acceptable ranges for the Argon2 parameters,
// ensuring that if someone changes these values, they remain within a secure and reasonable range.
const MIN_ARGON2_MEMORY_COST: u32 = 8192;    // Minimum: 8192 KiB (8 MiB)
const MAX_ARGON2_MEMORY_COST: u32 = 1048576;   // Maximum: 1048576 KiB (1 GiB)
const MIN_ARGON2_ITERATIONS: u32 = 1;          // At least 1 iteration is required.
const MAX_ARGON2_ITERATIONS: u32 = 10;         // More than 10 might be overly burdensome.
const MIN_ARGON2_PARALLELISM: u32 = 1;         // At least one lane.
const MAX_ARGON2_PARALLELISM: u32 = 8;         // More than 8 is rarely needed.

///
/// Deterministic Key Maker
///
/// This application generates a raw binary key file ("key.key") in a deterministic manner based on a user-provided password.
/// The process is as follows:
/// 1. Validate inputs (key size, password length, and Argon2 parameter ranges).
/// 2. Use Argon2 with specified parameters to derive a 32-byte seed from the password.
/// 3. Seed ChaCha20 (a cryptographically secure PRNG) with the derived seed.
/// 4. Generate the key data in chunks and write it directly to "key.key".
///
fn main() {
    // Expect exactly two command-line arguments: <size_in_bytes> and <password>
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <size_in_bytes> <password>", args[0]);
        exit(1);
    }

    // Parse the key size.
    let size: u64 = match args[1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Invalid size: '{}'", args[1]);
            exit(1);
        }
    };

    if size < 1 || size > MAX_SIZE {
        eprintln!("Error: size must be between 1 byte and 5GB (inclusive).");
        exit(1);
    }

    let password = &args[2];

    // Validate that the password is not empty.
    if password.is_empty() {
        eprintln!("Error: Password cannot be empty.");
        exit(1);
    }

    // Validate that the password is within the allowed maximum length.
    if password.len() > MAX_PASSWORD_LENGTH {
        eprintln!(
            "Error: Password is too long (max {} characters allowed).",
            MAX_PASSWORD_LENGTH
        );
        exit(1);
    }

    // Validate Argon2 parameter ranges to ensure they are within acceptable bounds.
    if ARGON2_MEMORY_COST < MIN_ARGON2_MEMORY_COST || ARGON2_MEMORY_COST > MAX_ARGON2_MEMORY_COST {
        eprintln!(
            "Error: Argon2 memory cost must be between {} and {} KiB.",
            MIN_ARGON2_MEMORY_COST, MAX_ARGON2_MEMORY_COST
        );
        exit(1);
    }

    if ARGON2_ITERATIONS < MIN_ARGON2_ITERATIONS || ARGON2_ITERATIONS > MAX_ARGON2_ITERATIONS {
        eprintln!(
            "Error: Argon2 iteration count must be between {} and {}.",
            MIN_ARGON2_ITERATIONS, MAX_ARGON2_ITERATIONS
        );
        exit(1);
    }

    if ARGON2_PARALLELISM < MIN_ARGON2_PARALLELISM || ARGON2_PARALLELISM > MAX_ARGON2_PARALLELISM {
        eprintln!(
            "Error: Argon2 parallelism (lanes) must be between {} and {}.",
            MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM
        );
        exit(1);
    }

    // Create the Argon2 parameters using the specified constants.
    // Params::new takes:
    // - memory cost (in KiB)
    // - time cost (number of iterations)
    // - parallelism (number of lanes)
    // - an optional secret (None in this case)
    let params = match Params::new(ARGON2_MEMORY_COST, ARGON2_ITERATIONS, ARGON2_PARALLELISM, None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error setting Argon2 parameters: {}", e);
            exit(1);
        }
    };

    // Create an Argon2 instance using the Argon2id variant (which offers resistance to side-channel attacks)
    // and version 1.3 (V0x13). The chosen parameters (memory, iterations, parallelism) define the computational cost.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Prepare a 32-byte buffer to hold the seed derived from the password.
    let mut seed = [0u8; 32];
    if let Err(e) = argon2.hash_password_into(password.as_bytes(), KDF_SALT.as_bytes(), &mut seed) {
        eprintln!("Error deriving key: {}", e);
        exit(1);
    }

    // Initialize the ChaCha20 PRNG with the derived seed.
    // ChaCha20 is a secure PRNG with an enormous period, ensuring that even very large keys do not exhibit repetition.
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Open the output file "key.key" in binary mode.
    let file = match File::create("key.key") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create file 'key.key': {}", e);
            exit(1);
        }
    };
    let mut writer = BufWriter::new(file);

    // Generate the key in chunks.
    // This approach supports the creation of keys as large as 5GB without consuming too much memory.
    let mut remaining = size;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    while remaining > 0 {
        let chunk = if remaining as usize > CHUNK_SIZE {
            CHUNK_SIZE
        } else {
            remaining as usize
        };
        rng.fill_bytes(&mut buffer[..chunk]);
        if let Err(e) = writer.write_all(&buffer[..chunk]) {
            eprintln!("Error writing to file: {}", e);
            exit(1);
        }
        remaining -= chunk as u64;
    }

    if let Err(e) = writer.flush() {
        eprintln!("Error flushing file: {}", e);
        exit(1);
    }

    println!("Deterministic key of {} bytes generated and saved to 'key.key'.", size);
}
