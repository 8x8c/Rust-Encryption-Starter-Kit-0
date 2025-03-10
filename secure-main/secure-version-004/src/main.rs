use std::{env, fs};
use std::io::{self, Write};
use rand::RngCore;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generates a pseudorandom keystream of the given length using a counter-mode HMAC construction.
/// The keystream is derived from the encryption key and a unique nonce.
fn generate_keystream(enc_key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length);
    let mut counter = 0u64;
    while keystream.len() < length {
        let mut data = Vec::with_capacity(nonce.len() + 8);
        data.extend_from_slice(nonce);
        data.extend_from_slice(&counter.to_le_bytes());
        let mut mac = HmacSha256::new_from_slice(enc_key)
            .expect("HMAC can take key of any size");
        mac.update(&data);
        let block = mac.finalize().into_bytes();
        keystream.extend_from_slice(&block);
        counter += 1;
    }
    keystream.truncate(length);
    keystream
}

/// XORs the data with the provided keystream.
fn xor_data(data: &[u8], keystream: &[u8]) -> Vec<u8> {
    data.iter().zip(keystream.iter()).map(|(&a, &b)| a ^ b).collect()
}

fn main() -> io::Result<()> {
    // Expect usage: <E|D> <input_file> <output_file>
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: <E|D> <input_file> <output_file>");
        std::process::exit(1);
    }
    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];

    // Load the encryption key and the MAC key from separate files.
    let enc_key = fs::read("key.key")?;
    let mac_key = fs::read("key1.key")?;
    let data = fs::read(input_file)?;

    if mode == "E" {
        // --- Encryption ---
        // Generate a 32-byte nonce.
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Derive a keystream of the same length as the plaintext.
        let keystream = generate_keystream(&enc_key, &nonce, data.len());
        let ciphertext = xor_data(&data, &keystream);

        // Compute HMAC (authentication tag) over nonce || ciphertext.
        let mut mac = HmacSha256::new_from_slice(&mac_key)
            .expect("HMAC can take key of any size");
        mac.update(&nonce);
        mac.update(&ciphertext);
        let auth_tag = mac.finalize().into_bytes();

        // Write output: nonce (32 bytes) || auth_tag (32 bytes) || ciphertext.
        let mut output = fs::File::create(output_file)?;
        output.write_all(&nonce)?;
        output.write_all(&auth_tag)?;
        output.write_all(&ciphertext)?;

        println!("Encryption successful.");
    } else {
        // --- Decryption ---
        // The file must at least contain the nonce and MAC tag.
        if data.len() < 64 {
            eprintln!("Error: Encrypted file too short.");
            std::process::exit(1);
        }
        // Extract nonce, authentication tag, and ciphertext.
        let nonce = &data[..32];
        let stored_auth_tag = &data[32..64];
        let ciphertext = &data[64..];

        // Verify the MAC before decryption.
        let mut mac = HmacSha256::new_from_slice(&mac_key)
            .expect("HMAC can take key of any size");
        mac.update(nonce);
        mac.update(ciphertext);
        if mac.verify_slice(stored_auth_tag).is_err() {
            eprintln!("Error: Authentication failed! File may have been tampered with.");
            std::process::exit(1);
        }

        // Reconstruct the keystream and recover the plaintext.
        let keystream = generate_keystream(&enc_key, nonce, ciphertext.len());
        let plaintext = xor_data(ciphertext, &keystream);

        fs::write(output_file, plaintext)?;
        println!("Decryption and authentication successful.");
    }
    Ok(())
}



