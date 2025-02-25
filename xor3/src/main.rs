// main.rs

use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process;

use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const NONCE_SIZE: usize = 16; // 128-bit nonce
const MAC_SIZE: usize = 32;   // HMAC-SHA256 output size

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: <E|D> <input_file> <output_file> <key_file>");
        process::exit(1);
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];
    let key_file = &args[4];

    if mode != "E" && mode != "D" {
        eprintln!("Invalid mode. Use 'E' for encrypt or 'D' for decrypt.");
        process::exit(1);
    }

    // Prevent overwriting the input file or an existing output file
    if input_file == output_file {
        eprintln!("Input and output file paths cannot be the same.");
        process::exit(1);
    }
    if file_exists(output_file) {
        eprintln!(
            "Output file '{}' already exists. Aborting to prevent overwrite.",
            output_file
        );
        process::exit(1);
    }

    // Load the key
    let mut key = Vec::new();
    if let Err(err) = load_file(key_file, &mut key) {
        eprintln!("Failed to load key: {}", err);
        process::exit(1);
    }

    // Load the input data
    let mut input_data = Vec::new();
    if let Err(err) = load_file(input_file, &mut input_data) {
        eprintln!("Failed to load input file: {}", err);
        process::exit(1);
    }

    // Basic key length check
    // For encryption, key must be >= plaintext length
    // For decryption, key must be >= (ciphertext length minus nonce+MAC)
    if (mode == "E" && key.len() < input_data.len()) ||
       (mode == "D" && key.len() < input_data.len().saturating_sub(NONCE_SIZE + MAC_SIZE)) {
        eprintln!("The key is too short. (Key length: {}, Input length: {})",
                  key.len(),
                  input_data.len());
        process::exit(1);
    }

    let mut output_data = Vec::new();

    match mode.as_str() {
        "E" => {
            // 1) Generate a random nonce
            let nonce = generate_random_bytes(NONCE_SIZE);

            // 2) Derive subkeys (encryption_subkey, hmac_subkey) from (key, nonce) using HKDF
            let (encryption_subkey, hmac_subkey) = derive_subkeys_with_hkdf(&key, &nonce);

            // 3) Generate a keystream from the encryption_subkey + nonce 
            //    (similar approach to the original generate_keystream, but we incorporate the encryption_subkey)
            let keystream = generate_keystream(&encryption_subkey, &nonce, input_data.len());

            // Prepend the nonce
            output_data.extend_from_slice(&nonce);

            // 4) XOR the plaintext with the key file AND the keystream
            let mut temp_data = Vec::new();
            xor_with_key_and_keystream(&input_data, &key, &keystream, &mut temp_data);
            output_data.extend_from_slice(&temp_data);

            // 5) Compute HMAC over (nonce + ciphertext) using the derived hmac_subkey
            let mac = generate_hmac(&hmac_subkey, &output_data);
            output_data.extend_from_slice(&mac);

            // Zeroize sensitive data
            zeroize_slices(&mut [ &mut key, &mut temp_data ]);
        }
        "D" => {
            if input_data.len() < NONCE_SIZE + MAC_SIZE {
                eprintln!("Invalid input file: missing nonce or MAC.");
                process::exit(1);
            }

            // 1) Separate nonce, ciphertext, and MAC
            let (nonce, rest) = input_data.split_at(NONCE_SIZE);
            let (ciphertext, received_mac) = rest.split_at(rest.len() - MAC_SIZE);

            // 2) Derive subkeys using the same key+nonce
            let (encryption_subkey, hmac_subkey) = derive_subkeys_with_hkdf(&key, nonce);

            // 3) Verify the HMAC before decryption 
            //    (compute HMAC on everything except the last 32 bytes, i.e. the MAC)
            verify_hmac(&hmac_subkey, &input_data[..input_data.len() - MAC_SIZE], received_mac);

            // 4) Generate the same keystream
            let keystream = generate_keystream(&encryption_subkey, nonce, ciphertext.len());

            // 5) XOR to get the original plaintext
            xor_with_key_and_keystream(ciphertext, &key, &keystream, &mut output_data);

            // Zeroize sensitive data
            zeroize_slices(&mut [ &mut key ]);
        }
        _ => unreachable!(),
    }

    // Finally, save the output
    if let Err(err) = save_file(output_file, &output_data) {
        eprintln!("Failed to save output file: {}", err);
        process::exit(1);
    }

    // Zeroize output_data if desired (this is the final ciphertext or plaintext).
    // In some cases you may want to keep plaintext in memory, so this is optional.
    // output_data.zeroize();
}

// -------------------- File I/O Helpers --------------------
fn load_file(filename: &str, buffer: &mut Vec<u8>) -> std::io::Result<()> {
    let mut file = File::open(filename)?;
    file.read_to_end(buffer)?;
    Ok(())
}

fn save_file(filename: &str, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(data)?;
    Ok(())
}

fn file_exists(filename: &str) -> bool {
    Path::new(filename).exists()
}

// -------------------- Randomness --------------------
fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    OsRng.fill_bytes(&mut buffer);
    buffer
}

// -------------------- HKDF Key Derivation --------------------
fn derive_subkeys_with_hkdf(master_key: &[u8], salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);

    let mut encryption_subkey = vec![0u8; 32];
    let mut hmac_subkey = vec![0u8; 32];

    hk.expand(b"encryption_subkey", &mut encryption_subkey)
        .expect("HKDF expand failed for encryption subkey");
    hk.expand(b"hmac_subkey", &mut hmac_subkey)
        .expect("HKDF expand failed for hmac subkey");

    (encryption_subkey, hmac_subkey)
}

// -------------------- Keystream Generation --------------------
fn generate_keystream(encryption_subkey: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length);
    let mut counter = 0u64;

    // We take the original XOR-based approach but incorporate the encryption_subkey into the hash each time
    while keystream.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(encryption_subkey);
        hasher.update(nonce);
        hasher.update(&counter.to_be_bytes());
        let hash_output = hasher.finalize();

        // Only take as many bytes as we need
        let chunk = if keystream.len() + hash_output.len() > length {
            &hash_output[..(length - keystream.len())]
        } else {
            &hash_output
        };
        keystream.extend_from_slice(chunk);

        counter += 1;
    }

    keystream
}

// -------------------- XOR and HMAC --------------------
fn xor_with_key_and_keystream(
    input: &[u8],
    key: &[u8],
    keystream: &[u8],
    output: &mut Vec<u8>,
) {
    for i in 0..input.len() {
        let byte = input[i] ^ key[i] ^ keystream[i];
        output.push(byte);
    }
}

fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(key: &[u8], data: &[u8], received_mac: &[u8]) {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    if mac.verify_slice(received_mac).is_err() {
        eprintln!("MAC verification failed. Data may have been tampered with.");
        process::exit(1);
    }
}

// -------------------- Zeroize Helper --------------------
fn zeroize_slices(slices: &mut [&mut [u8]]) {
    for slice in slices.iter_mut() {
        slice.zeroize();
    }
}
