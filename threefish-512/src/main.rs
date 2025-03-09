use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use anyhow::Result;
use clap::{Arg, Command};

use cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut};
use threefish::Threefish512;

// 64-byte (512-bit) key
static KEY_64_BYTES: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F,

    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B,
    0x1C, 0x1D, 0x1E, 0x1F,

    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B,
    0x2C, 0x2D, 0x2E, 0x2F,

    0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x3E, 0x3F,
];

// 16-byte (128-bit) tweak
static TWEAK_16_BYTES: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F,
];

fn main() -> Result<()> {
    let matches = Command::new("threefish_cli")
        .version("0.1.0")
        .subcommand_required(true)
        .subcommand(
            Command::new("encrypt")
                .arg(Arg::new("input").required(true).index(1))
                .arg(Arg::new("output").required(true).index(2)),
        )
        .subcommand(
            Command::new("decrypt")
                .arg(Arg::new("input").required(true).index(1))
                .arg(Arg::new("output").required(true).index(2)),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_m)) => {
            let input_path = sub_m.get_one::<String>("input").unwrap();
            let output_path = sub_m.get_one::<String>("output").unwrap();
            encrypt_file(input_path, output_path)?;
        }
        Some(("decrypt", sub_m)) => {
            let input_path = sub_m.get_one::<String>("input").unwrap();
            let output_path = sub_m.get_one::<String>("output").unwrap();
            decrypt_file(input_path, output_path)?;
        }
        _ => {}
    }
    Ok(())
}

fn encrypt_file(input_path: &str, output_path: &str) -> Result<()> {
    let mut input_data = Vec::new();
    File::open(input_path)?.read_to_end(&mut input_data)?;

    let encrypted = threefish_ecb_encrypt(&input_data)?;
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    out.write_all(&encrypted)?;
    println!("Encrypted {input_path} -> {output_path}");
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str) -> Result<()> {
    let mut encrypted_data = Vec::new();
    File::open(input_path)?.read_to_end(&mut encrypted_data)?;

    if encrypted_data.len() % 64 != 0 {
        anyhow::bail!("Encrypted data not a multiple of 64 bytes. Possibly corrupted?");
    }

    let decrypted = threefish_ecb_decrypt(&encrypted_data)?;
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    out.write_all(&decrypted)?;
    println!("Decrypted {input_path} -> {output_path}");
    Ok(())
}

fn threefish_ecb_encrypt(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(data.len());

    for block in data.chunks(64) {
        // zero-pad if needed
        let mut block_buf = [0u8; 64];
        block_buf[..block.len()].copy_from_slice(block);
        let mut block_ga = GenericArray::clone_from_slice(&block_buf);

        // must declare cipher as mutable to use encrypt_block_mut
        let mut cipher = Threefish512::new_with_tweak(&KEY_64_BYTES, &TWEAK_16_BYTES);
        cipher.encrypt_block_mut(&mut block_ga);

        output.extend_from_slice(&block_ga);
    }
    Ok(output)
}

fn threefish_ecb_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(data.len());

    for block in data.chunks(64) {
        let mut block_ga = GenericArray::clone_from_slice(block);

        let mut cipher = Threefish512::new_with_tweak(&KEY_64_BYTES, &TWEAK_16_BYTES);
        cipher.decrypt_block_mut(&mut block_ga);

        output.extend_from_slice(&block_ga);
    }
    Ok(output)
}

