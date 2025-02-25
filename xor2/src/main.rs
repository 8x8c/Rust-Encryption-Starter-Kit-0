use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
    process,
};

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

// We'll use HMAC-SHA256 for integrity checks.
type HmacSha256 = Hmac<Sha256>;

fn main() {
    if let Err(e) = run() {
        log_error(&format!("Error: {}", e));
        eprintln!("An error occurred. Check 'error.txt' for details.");
        process::exit(1);
    }
}

/// Parses the arguments: `e file.txt` (encrypt) or `d file.txt` (decrypt).
fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Usage: <app> <e|d> <file>",
        ));
    }

    let mode = &args[1];     // "e" or "d"
    let filename = &args[2]; // e.g. "file.txt"

    // 1. Ensure `mac.key` exists; if not, create one with random data.
    create_mac_key_if_missing()?;

    // 2. Proceed based on user command.
    match mode.as_str() {
        "e" => encrypt_and_verify(filename),
        "d" => decrypt_and_verify(filename),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid mode. Use 'e' for encrypt or 'd' for decrypt.",
        )),
    }
}

/// Creates a new 32-byte `mac.key` if it does not exist (demo only).
fn create_mac_key_if_missing() -> io::Result<()> {
    let path = Path::new("mac.key");
    if !path.exists() {
        let mut file = File::create(path)?;
        let mut random_bytes = [0u8; 32];
        // Fill an array with secure random bytes from the OS.
        OsRng.fill_bytes(&mut random_bytes);
        file.write_all(&random_bytes)?;
        println!("Created a new 32-byte mac.key (demo only).");
    }
    Ok(())
}

/// Encrypts the file, writes a .mac file, then verifies the result automatically.
fn encrypt_and_verify(filename: &str) -> io::Result<()> {
    // 1. Read plaintext from disk.
    let mut plaintext = fs::read(filename)?;

    // 2. Load keys: XOR key + MAC key.
    let xor_key = load_key("xor.key")?;
    let mac_key = load_key("mac.key")?;

    // 3. Check XOR key length.
    if xor_key.len() < plaintext.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "xor.key is smaller than the file to encrypt.",
        ));
    }

    // 4. Compute HMAC over (plaintext || length) => tag as Vec<u8>.
    let mut mac = HmacSha256::new_from_slice(&mac_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid MAC key"))?;
    mac.update(&plaintext);
    mac.update(&(plaintext.len() as u64).to_le_bytes());
    let tag = mac.finalize().into_bytes().to_vec(); // convert GenericArray -> Vec<u8>

    // 5. Write the HMAC to a separate file: "file.txt.mac"
    let mac_filename = format!("{}.mac", filename);
    fs::write(&mac_filename, &tag)?;

    // 6. XOR the plaintext in-place.
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte ^= xor_key[i];
    }

    // 7. Overwrite the original file with the ciphertext (temp file for safety).
    let temp_filename = format!("{}.tmp", filename);
    fs::write(&temp_filename, &plaintext)?;
    fs::rename(&temp_filename, filename)?;

    println!("Encrypted '{}' and wrote MAC to '{}'.", filename, mac_filename);

    // 8. Automatically verify the newly encrypted file.
    verify_ciphertext(filename, &xor_key, &mac_key)?;

    println!("Automatic verification after encryption succeeded.");
    Ok(())
}

/// Decrypts the file, verifies via .mac, then automatically checks the resulting plaintext.
fn decrypt_and_verify(filename: &str) -> io::Result<()> {
    // 1. Read ciphertext.
    let mut ciphertext = fs::read(filename)?;

    // 2. Load keys: XOR key + MAC key.
    let xor_key = load_key("xor.key")?;
    let mac_key = load_key("mac.key")?;

    // 3. Read stored MAC from "file.txt.mac".
    let mac_filename = format!("{}.mac", filename);
    if !Path::new(&mac_filename).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("MAC file '{}' not found.", mac_filename),
        ));
    }
    let stored_tag = fs::read(&mac_filename)?; // a Vec<u8>

    // 4. XOR decrypt in-place to recover plaintext.
    if xor_key.len() < ciphertext.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "xor.key is smaller than the ciphertext.",
        ));
    }
    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte ^= xor_key[i];
    }
    let plaintext = ciphertext; // now the recovered plaintext

    // 5. Compute HMAC over (plaintext || length) => recomputed_tag
    let mut mac = HmacSha256::new_from_slice(&mac_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid MAC key"))?;
    mac.update(&plaintext);
    mac.update(&(plaintext.len() as u64).to_le_bytes());
    let recomputed_tag = mac.finalize().into_bytes().to_vec();

    if recomputed_tag != stored_tag {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Integrity check failed. The file may be tampered with.",
        ));
    }

    // 6. Write the recovered plaintext back to disk (temp file).
    let temp_filename = format!("{}.tmp", filename);
    fs::write(&temp_filename, &plaintext)?;
    fs::rename(&temp_filename, filename)?;

    println!("Decrypted '{}' successfully.", filename);

    // 7. Automatically verify the newly decrypted file.
    verify_plaintext(filename, &mac_key)?;

    println!("Automatic verification after decryption succeeded.");
    Ok(())
}

/// Verify the newly encrypted file by reading the ciphertext, XORing in-memory, and checking the MAC.
fn verify_ciphertext(filename: &str, xor_key: &[u8], mac_key: &[u8]) -> io::Result<()> {
    // 1. Read the ciphertext from file.
    let mut ciphertext = fs::read(filename)?;

    // 2. XOR in-place to get plaintext.
    if xor_key.len() < ciphertext.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "xor.key is smaller than the ciphertext.",
        ));
    }
    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte ^= xor_key[i];
    }

    // 3. Read the stored MAC and recompute the MAC on the plaintext.
    let mac_filename = format!("{}.mac", filename);
    let stored_tag = fs::read(&mac_filename)?; // Vec<u8>

    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid MAC key"))?;
    mac.update(&ciphertext);
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    let recomputed_tag = mac.finalize().into_bytes().to_vec();

    if recomputed_tag != stored_tag {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Ciphertext integrity check failed right after encryption.",
        ));
    }

    Ok(())
}

/// Verify the newly decrypted file by reading the plaintext, computing the MAC, and comparing it.
fn verify_plaintext(filename: &str, mac_key: &[u8]) -> io::Result<()> {
    // 1. Read the plaintext from disk.
    let plaintext = fs::read(filename)?;

    // 2. Read the stored MAC
    let mac_filename = format!("{}.mac", filename);
    let stored_tag = fs::read(mac_filename)?; // Vec<u8>

    // 3. Compute MAC over (plaintext || length) => recomputed_tag
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid MAC key"))?;
    mac.update(&plaintext);
    mac.update(&(plaintext.len() as u64).to_le_bytes());
    let recomputed_tag = mac.finalize().into_bytes().to_vec();

    if recomputed_tag != stored_tag {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Plaintext integrity check failed right after decryption.",
        ));
    }

    Ok(())
}

/// Helper to load a key (for XOR or MAC) from disk.
fn load_key(filename: &str) -> io::Result<Vec<u8>> {
    if !Path::new(filename).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key file '{}' not found.", filename),
        ));
    }
    fs::read(filename)
}

/// Logs errors to `error.txt`, appending if the file already exists.
fn log_error(msg: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("error.txt")
    {
        let _ = writeln!(f, "{}", msg);
    }
}
