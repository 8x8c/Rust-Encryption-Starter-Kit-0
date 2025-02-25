use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    process,
};

fn main() {
    if let Err(e) = run() {
        // If an error occurs, log it to error.txt and exit with a failure code
        log_error(&format!("Error: {}", e));
        eprintln!("An error occurred. Check 'error.txt' for details.");
        process::exit(1);
    }
}

fn run() -> io::Result<()> {
    // Read command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Usage: <app> <file_to_encrypt>",
        ));
    }
    let filename = &args[1];

    // Hard-coded key filename (in the same directory)
    let key_filename = "key.key";

    // Check if the key file exists
    if !Path::new(key_filename).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key file '{}' does not exist.", key_filename),
        ));
    }

    // 1. Read the file to be encrypted
    let mut file_data = fs::read(filename)?;

    // 2. Read the key file into memory
    let key_data = fs::read(key_filename)?;

    // 3. Ensure the key is large enough
    if key_data.len() < file_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Key file '{}' is smaller than '{}'.",
                key_filename, filename
            ),
        ));
    }

    // 4. Perform XOR in-place
    for (i, byte) in file_data.iter_mut().enumerate() {
        *byte ^= key_data[i];
    }

    // 5. Write encrypted data to a temporary file (to preserve data integrity)
    let temp_filename = format!("{}.tmp", filename);
    fs::write(&temp_filename, &file_data)?;

    // 6. Atomically replace the original file with the encrypted file
    fs::rename(&temp_filename, filename)?;

    println!(
        "Successfully XOR-encrypted '{}' with key '{}'.",
        filename, key_filename
    );

    Ok(())
}

/// Logs the given error message to 'error.txt', appending if the file already exists.
fn log_error(msg: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("error.txt")
    {
        let _ = writeln!(f, "{}", msg);
    }
}
