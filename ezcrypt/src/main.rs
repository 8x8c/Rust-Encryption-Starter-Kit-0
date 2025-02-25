use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, PasswordHash}};
use rand::RngCore;
use rand::rngs::OsRng;

use anyhow::{anyhow, bail, Result};
use blake3;

const STATIC_SALT: &str = "MY_STATIC_SALT_VALUE";
const PEPPER: &str = "MY_STATIC_PEPPER_VALUE";
const MAGIC_HEADER: &[u8] = b"ENCFILE";
const NONCE_SIZE: usize = 12;

fn file_is_encrypted(path: &str) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; MAGIC_HEADER.len()];
    let bytes_read = file.read(&mut buffer)?;

    if bytes_read < MAGIC_HEADER.len() {
        return Ok(false);
    }

    Ok(&buffer == MAGIC_HEADER)
}

fn derive_key(file_salt: &[u8]) -> Result<Key<Aes256Gcm>> {
    let combined = format!("{STATIC_SALT}{PEPPER}");
    let argon2 = Argon2::default();

    // Convert static salt+pepper to a SaltString
    let combined_salt = SaltString::b64_encode(combined.as_bytes())
        .map_err(|e| anyhow!("Invalid salt encoding: {e}"))?;

    // Instead of .context(...), use map_err to attach context
    let hash = argon2
        .hash_password(file_salt, &combined_salt)
        .map_err(|e| anyhow!("Argon2 hashing error: {e}"))?
        .to_string();

    // Now parse the hash. Again, we can’t use .context(...)
    let parsed_hash = PasswordHash::new(&hash)
        .map_err(|e| anyhow!("Failed to parse Argon2 hash: {e}"))?;

    // Verify
    let ok = argon2.verify_password(file_salt, &parsed_hash).is_ok();
    if !ok {
        bail!("Could not verify Argon2 hash");
    }

    // Use BLAKE3 to reduce the hash string to 32 bytes
    let derived = blake3::hash(hash.as_bytes()).as_bytes().clone();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&derived[..32]);

    Ok(Key::<Aes256Gcm>::from_slice(&key_bytes).clone())
}

fn encrypt_file(filename: &str) -> Result<()> {
    // Generate random salt
    let mut file_salt = [0u8; 16];
    OsRng.fill_bytes(&mut file_salt);

    let key = derive_key(&file_salt)?;
    let cipher = Aes256Gcm::new(&key);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Read original file
    let mut original_data = Vec::new();
    {
        let mut input_file = File::open(filename)
            .map_err(|e| anyhow!("Failed to open file {filename} for reading: {e}"))?;
        input_file.read_to_end(&mut original_data)?;
    }

    // Instead of .with_context(...), use map_err
    let ciphertext = cipher
        .encrypt(nonce, original_data.as_ref())
        .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;

    let mut new_file_data = Vec::new();
    new_file_data.extend_from_slice(MAGIC_HEADER);
    new_file_data.extend_from_slice(&file_salt);
    new_file_data.extend_from_slice(&nonce_bytes);
    new_file_data.extend_from_slice(&ciphertext);

    // Write atomically
    let temp_name = format!("{filename}.tmp");
    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_name)
            .map_err(|e| anyhow!("Failed to open temp file {temp_name}: {e}"))?;
        tmp_file.write_all(&new_file_data)?;
        tmp_file.flush()?;
    }

    std::fs::rename(&temp_name, filename)
        .map_err(|e| anyhow!("Failed to rename {temp_name} to {filename}: {e}"))?;

    println!("File successfully encrypted: {filename}");
    Ok(())
}

fn decrypt_file(filename: &str) -> Result<()> {
    // Read entire file
    let mut file_data = Vec::new();
    {
        let mut file = File::open(filename)?;
        file.read_to_end(&mut file_data)?;
    }

    if file_data.len() < MAGIC_HEADER.len() {
        bail!("File too small, not a valid encrypted file?");
    }
    if &file_data[..MAGIC_HEADER.len()] != MAGIC_HEADER {
        bail!("Magic header mismatch, not an encrypted file?");
    }

    // Offsets
    let offset_salt = MAGIC_HEADER.len();
    let offset_nonce = offset_salt + 16;
    let offset_ciphertext = offset_nonce + NONCE_SIZE;

    if file_data.len() < offset_ciphertext {
        bail!("Encrypted file is missing salt/nonce data.");
    }

    let file_salt = &file_data[offset_salt..offset_salt+16];
    let nonce_bytes = &file_data[offset_nonce..offset_nonce+NONCE_SIZE];
    let ciphertext = &file_data[offset_ciphertext..];

    let key = derive_key(file_salt)?;
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce_bytes);

    // Use map_err again
    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES-GCM decryption failed: {e}"))?;

    // Write atomically
    let temp_name = format!("{filename}.tmp");
    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_name)?;
        tmp_file.write_all(&decrypted_data)?;
        tmp_file.flush()?;
    }
    std::fs::rename(&temp_name, filename)?;

    println!("File successfully decrypted: {filename}");
    Ok(())
}

fn ensure_in_current_dir(filename: &str) -> Result<()> {
    let path = Path::new(filename);
    if path.parent().map_or(false, |p| p != Path::new("")) {
        bail!("File path is not in the current directory.");
    }
    Ok(())
}

fn main() -> Result<()> {
    println!("Enter the file name (in the current directory):");
    let mut filename = String::new();
    std::io::stdin().read_line(&mut filename)?;
    let filename = filename.trim();

    ensure_in_current_dir(filename)?;

    let is_encrypted = file_is_encrypted(filename)?;
    if is_encrypted {
        println!("Detected encrypted file, proceeding to decrypt...");
        decrypt_file(filename)?;
    } else {
        println!("Detected unencrypted file, proceeding to encrypt...");
        encrypt_file(filename)?;
    }

    Ok(())
}
