use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::{
    fs,
    io::Write,
    path::PathBuf,
};

/// A simple secure file encryption CLI tool
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Path to the input file
        input: PathBuf,
        /// Path to the output file (encrypted)
        output: PathBuf,
        /// Password for encryption
        #[arg(short, long)]
        password: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Path to the input file (encrypted)
        input: PathBuf,
        /// Path to the output file (decrypted)
        output: PathBuf,
        /// Password for decryption
        #[arg(short, long)]
        password: String,
    },
}

const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output, password } => {
            let plaintext = fs::read(&input)?;

            // Generate a random salt (16 bytes)
            let mut salt = [0u8; SALT_LENGTH];
            rand::thread_rng().fill_bytes(&mut salt);

            // Derive a 32-byte key from the password using Argon2id
            let argon2 = Argon2::default();
            let mut key = [0u8; KEY_LENGTH];
            argon2
                .hash_password_into(password.as_bytes(), &salt, &mut key)
                .map_err(|e| anyhow::anyhow!("Key derivation failed: {:?}", e))?;

            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| anyhow::anyhow!("Error creating cipher: {:?}", e))?;

            // Generate a random nonce (12 bytes)
            let mut nonce_bytes = [0u8; NONCE_LENGTH];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Encrypt the plaintext
            let ciphertext = cipher
                .encrypt(nonce, plaintext.as_ref())
                .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

            // Write out the salt, nonce, then ciphertext.
            // (Salt and nonce are not secret, but needed for key derivation and decryption.)
            let mut out_file = fs::File::create(&output)?;
            out_file.write_all(&salt)?;
            out_file.write_all(&nonce_bytes)?;
            out_file.write_all(&ciphertext)?;
            println!("File encrypted successfully.");
        }
        Commands::Decrypt { input, output, password } => {
            let data = fs::read(&input)?;
            if data.len() < SALT_LENGTH + NONCE_LENGTH {
                return Err(anyhow::anyhow!("Input file is too short to contain salt and nonce"));
            }
            // Split the data into salt, nonce, and ciphertext
            let salt = &data[..SALT_LENGTH];
            let nonce_bytes = &data[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH];
            let ciphertext = &data[SALT_LENGTH + NONCE_LENGTH..];

            // Derive the same key from the password using the extracted salt
            let argon2 = Argon2::default();
            let mut key = [0u8; KEY_LENGTH];
            argon2
                .hash_password_into(password.as_bytes(), salt, &mut key)
                .map_err(|e| anyhow::anyhow!("Key derivation failed: {:?}", e))?;

            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| anyhow::anyhow!("Error creating cipher: {:?}", e))?;
            let nonce = Nonce::from_slice(nonce_bytes);

            // Decrypt the ciphertext
            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
            fs::write(&output, plaintext)?;
            println!("File decrypted successfully.");
        }
    }

    Ok(())
}


