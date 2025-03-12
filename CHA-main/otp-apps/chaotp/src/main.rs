use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};

fn main() -> io::Result<()> {
    // Determine mode and validate command line arguments.
    // If the first argument is "-over", we'll overwrite the input file.
    let args: Vec<String> = env::args().collect();
    let (input_path, output_path, atomic_overwrite) = match args.len() {
        3 => {
            if args[1] == "-over" {
                (args[2].clone(), args[2].clone(), true)
            } else {
                (args[1].clone(), args[2].clone(), false)
            }
        },
        _ => {
            eprintln!("Usage:");
            eprintln!("  {} <input_file> <output_file>", args[0]);
            eprintln!("  {} -over <input_file>", args[0]);
            std::process::exit(1);
        }
    };

    // Read the entire input file into memory.
    let input_data = fs::read(&input_path)?;
    
    // Read the key from the key file "key.key" in the current directory.
    let key_data = fs::read("key.key")?;
    
    // Ensure the key is at least as large as the input data.
    if key_data.len() < input_data.len() {
        eprintln!("Error: key is smaller than the input file.");
        std::process::exit(1);
    }
    
    // XOR each byte of the input with the corresponding byte from the key.
    let result: Vec<u8> = input_data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_data[i])
        .collect();

    if atomic_overwrite {
        // For atomic overwrite, write the processed data to a temporary file
        // in the same directory as the input file.
        let tmp_path = format!("{}.tmp", input_path);

        {
            // Open (or create) the temporary file, truncating it if it exists.
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;

            // Write the XOR result to the temporary file.
            tmp_file.write_all(&result)?;
            // Flush and sync the file to ensure all data is committed to disk.
            tmp_file.flush()?;
            tmp_file.sync_all()?;
        }

        // Atomically replace the input file with the temporary file.
        // On most platforms, fs::rename is atomic if both files reside in the same directory.
        fs::rename(&tmp_path, &input_path)?;
    } else {
        // Normal mode: write the processed data to the specified output file.
        fs::write(&output_path, result)?;
    }
    
    Ok(())
}

