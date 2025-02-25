// main.rs

use anyhow::{anyhow, bail, Context, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use clap::{ArgAction, Args, Parser, Subcommand};
use rand::RngCore;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
// For .decode() method
use base64::{engine::general_purpose::STANDARD, Engine};
// For securely zeroing plaintext
use zeroize::Zeroize;

/////////////////////////////////////////////////////////////////////////////////////
// 1) Hard-coded Base64-encoded 32-byte key (no "AGE-SECRET-KEY-" prefix).
//    NOTE: This is purely for example. In production, do NOT hard-code secrets.
/////////////////////////////////////////////////////////////////////////////////////
static BASE64_KEY: &str = "BUrKBD6FuC4OPz4eBLTicqB8IBIcMZTe3UP4lnTi5+c=";

/////////////////////////////////////////////////////////////////////////////////////
// 2) Magic bytes to indicate the file is AES-GCM encrypted by this tool.
//    We prepend these to the nonce/ciphertext, so we can detect "already-encrypted" files.
/////////////////////////////////////////////////////////////////////////////////////
static MAGIC_BYTES: &[u8] = b"AGCM";

/////////////////////////////////////////////////////////////////////////////////////
// 3) Additional Authenticated Data (AAD). Could be anything relevant (tool name, version, etc.)
/////////////////////////////////////////////////////////////////////////////////////
static AAD_DATA: &[u8] = b"MyAES256GCMTool";

#[derive(Parser)]
#[command(author, version, about = "AES-256-GCM file encrypter/decrypter")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt the file in-place (with an atomic overwrite).
    Encrypt(FileOpts),
    /// Decrypt the file in-place (with an atomic overwrite).
    Decrypt(FileOpts),
}

#[derive(Args)]
struct FileOpts {
    /// Path to the file to encrypt/decrypt.
    #[arg(short, long)]
    path: PathBuf,

    /// Overwrite the file even if it already looks encrypted/decrypted.
    #[arg(short, long, action = ArgAction::SetTrue)]
    force: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1) Decode the Base64 key (must be exactly 32 bytes)
    let key_bytes = parse_base64_key(BASE64_KEY)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // 2) Dispatch encrypt/decrypt
    match cli.command {
        Commands::Encrypt(opts) => encrypt_file_in_place(&opts.path, aes_key, opts.force)?,
        Commands::Decrypt(opts) => decrypt_file_in_place(&opts.path, aes_key, opts.force)?,
    }

    Ok(())
}

// -------------------------------------------------------------------------
// parse_base64_key: Decodes 32 raw bytes from a standard Base64 string
// -------------------------------------------------------------------------
fn parse_base64_key(encoded: &str) -> Result<[u8; 32]> {
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|e| anyhow!("Failed to decode Base64 key: {e}"))?;

    if decoded.len() != 32 {
        bail!(
            "Decoded key must be exactly 32 bytes (found {})",
            decoded.len()
        );
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

// -------------------------------------------------------------------------
// encrypt_file_in_place: AES-256-GCM encryption with atomic overwrite
// -------------------------------------------------------------------------
fn encrypt_file_in_place(path: &Path, key: &Key<Aes256Gcm>, force: bool) -> Result<()> {
    // Read file contents
    let mut plaintext = read_entire_file(path)
        .with_context(|| format!("Failed to read file '{}'", path.display()))?;

    // Check if file already "looks encrypted"
    if !force && file_looks_encrypted(&plaintext) {
        bail!(
            "Refusing to encrypt an already-encrypted file ({}). Use --force to override.",
            path.display()
        );
    }

    // 1) Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 2) Encrypt
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: AAD_DATA, // Add AAD here
            },
        )
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    // 3) Build final data = MAGIC + Nonce + Ciphertext(+Tag)
    let mut final_data =
        Vec::with_capacity(MAGIC_BYTES.len() + nonce_bytes.len() + ciphertext.len());
    final_data.extend_from_slice(MAGIC_BYTES);
    final_data.extend_from_slice(&nonce_bytes);
    final_data.extend_from_slice(&ciphertext);

    // Securely zero the plaintext from memory
    plaintext.zeroize();

    // 4) Atomically overwrite the original file
    atomic_overwrite_file(path, &final_data)
        .with_context(|| format!("Failed to overwrite file '{}'", path.display()))?;

    println!("File encrypted successfully: {}", path.display());
    Ok(())
}

// -------------------------------------------------------------------------
// decrypt_file_in_place: AES-256-GCM decryption with atomic overwrite
// -------------------------------------------------------------------------
fn decrypt_file_in_place(path: &Path, key: &Key<Aes256Gcm>, force: bool) -> Result<()> {
    // Read entire file
    let encrypted_data = read_entire_file(path)
        .with_context(|| format!("Failed to read file '{}'", path.display()))?;

    // Check if file is "not encrypted"
    if !force && !file_looks_encrypted(&encrypted_data) {
        bail!(
            "Refusing to decrypt a file that doesn't look encrypted ({}). Use --force to override.",
            path.display()
        );
    }

    // Must be at least: MAGIC + 12 bytes for nonce + 16 bytes for GCM tag
    if encrypted_data.len() < MAGIC_BYTES.len() + 12 + 16 {
        bail!("File too small to contain magic + nonce + GCM tag");
    }

    // 1) Split out the magic bytes, confirm it matches
    let magic_len = MAGIC_BYTES.len();
    let (magic_part, rest) = encrypted_data.split_at(magic_len);
    if magic_part != MAGIC_BYTES {
        bail!("Invalid magic bytes, not an AES-GCM file or corrupted");
    }

    // 2) Next 12 bytes are the nonce
    let (nonce_bytes, ciphertext_with_tag) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 3) Decrypt
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: AAD_DATA, // same AAD as used in encryption
            },
        )
        .map_err(|e| anyhow!("Decryption failed: {e}"))?;

    // 4) Atomic overwrite with the recovered plaintext
    atomic_overwrite_file(path, &plaintext)
        .with_context(|| format!("Failed to overwrite file '{}'", path.display()))?;

    println!("File decrypted successfully: {}", path.display());
    Ok(())
}

// -------------------------------------------------------------------------
// file_looks_encrypted: check if bytes start with MAGIC_BYTES
// -------------------------------------------------------------------------
fn file_looks_encrypted(file_data: &[u8]) -> bool {
    file_data.len() >= MAGIC_BYTES.len() && file_data.starts_with(MAGIC_BYTES)
}

// -------------------------------------------------------------------------
// read_entire_file: read file contents into a Vec<u8>
// -------------------------------------------------------------------------
fn read_entire_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let mut buffer = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// -------------------------------------------------------------------------
// atomic_overwrite_file: write to a temp file, then rename over original
// -------------------------------------------------------------------------
fn atomic_overwrite_file(path: &Path, data: &[u8]) -> Result<()> {
    let parent_dir = path
        .parent()
        .ok_or_else(|| anyhow!("Cannot find parent directory of {:?}", path))?;

    // Create a temporary file
    let tmp_path = parent_dir.join(format!(".{}.tmp", Uuid::new_v4()));
    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| format!("Failed to create temp file '{}'", tmp_path.display()))?;
        tmp_file
            .write_all(data)
            .with_context(|| "Failed to write data to temp file")?;
        tmp_file.sync_all()?; // flush data + metadata
    }

    // Rename the temp file over the original (atomic on same filesystem)
    // If rename fails, try to remove the temp file so we don't leave orphans
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!("Failed to rename temp file: {e}"));
    }

    // Try to sync the directory for metadata durability (best effort).
    if let Ok(dir_file) = File::open(parent_dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}
