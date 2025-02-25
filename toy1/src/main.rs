use std::env;
use std::fs::{self, File};
use std::io::{self, Write};

/// Derive a 256–bit key from the password by iterating SHA–256 100,000 times.
fn derive_key(password: &str) -> [u8; 32] {
    // Start with the SHA–256 of the password bytes.
    let mut key = sha256(password.as_bytes());
    // Iteratively hash the result to slow down brute–force attacks.
    for _ in 0..100_000 {
        key = sha256(&key);
    }
    key
}

/// A keystream generator using SHA–256 in counter mode.
/// Each block is computed as: SHA256(key || counter)
struct Keystream {
    key: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    pos: usize,
}

impl Keystream {
    fn new(key: [u8; 32]) -> Self {
        // Set pos to 32 so that a new block is generated on the first next() call.
        Keystream {
            key,
            counter: 0,
            buffer: [0u8; 32],
            pos: 32,
        }
    }

    /// Refill the internal buffer by computing SHA256(key || counter).
    fn refill(&mut self) {
        let mut input = Vec::with_capacity(32 + 8);
        input.extend_from_slice(&self.key);
        input.extend_from_slice(&self.counter.to_be_bytes());
        self.buffer = sha256(&input);
        self.pos = 0;
        self.counter += 1;
    }
}

impl Iterator for Keystream {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.pos >= self.buffer.len() {
            self.refill();
        }
        let byte = self.buffer[self.pos];
        self.pos += 1;
        Some(byte)
    }
}

/// Process the file: verify its location, read its content,
/// XOR with a keystream derived from the password, and atomically replace it.
fn process_file(path: &str, password: &str) -> io::Result<()> {
    // Get the current executable's path and canonicalize its directory.
    let exe_path = env::current_exe()?;
    let exe_dir = exe_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "Executable has no parent directory")
    })?;
    let exe_dir = fs::canonicalize(exe_dir)?;

    // Canonicalize the file path and then canonicalize its parent directory.
    let file_path = fs::canonicalize(path)?;
    let file_parent = file_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "File has no parent directory")
    })?;
    let file_parent = fs::canonicalize(file_parent)?;

    // Check that the file's directory is the same as the executable's directory.
    if file_parent != exe_dir {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "File must be in the same directory as the executable.",
        ));
    }

    // Read the original file.
    let data = fs::read(&file_path)?;

    // Derive a key from the password.
    let key = derive_key(password);

    // Create a keystream generator from the key.
    let mut keystream = Keystream::new(key);

    // Process the data by XORing each byte with the next keystream byte.
    let processed: Vec<u8> = data.into_iter().map(|b| b ^ keystream.next().unwrap()).collect();

    // Create a temporary file path in the same directory.
    let mut temp_path = file_path.clone();
    if let Some(file_name) = file_path.file_name() {
        let temp_file_name = format!("{}.tmp", file_name.to_string_lossy());
        temp_path.set_file_name(temp_file_name);
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "Invalid file name"));
    }

    // Write the processed data to the temporary file.
    {
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(&processed)?;
        temp_file.sync_all()?;
    }

    // Atomically replace the original file with the temporary file.
    fs::rename(temp_path, file_path)?;

    Ok(())
}

/// Print usage instructions.
fn print_usage(program: &str) {
    eprintln!("Usage: {} <file> <password>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        print_usage(&args[0]);
        return;
    }

    let file_path = &args[1];
    let password = &args[2];

    match process_file(file_path, password) {
        Ok(()) => println!("File processed successfully."),
        Err(e) => eprintln!("Error processing file: {}", e),
    }
}

/// ---
///
/// Below is a minimal SHA–256 implementation using only the standard library.
/// Note: This is a straightforward implementation for demonstration purposes and
/// has not been optimized for performance.
///
/// SHA–256 processes data in 512–bit (64–byte) chunks and produces a 256–bit (32–byte) hash.
fn sha256(data: &[u8]) -> [u8; 32] {
    // Pre-processing (padding)
    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 64);
    padded.extend_from_slice(data);
    padded.push(0x80); // Append the '1' bit (and seven 0 bits)

    // Append 0 ≤ k < 512 bits '0', so that the resulting length (in bytes)
    // is congruent to 56 modulo 64.
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }

    // Append length as a 64–bit big–endian integer.
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Initialize hash values.
    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;

    // Constants defined in the SHA–256 specification.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Process the message in successive 512–bit chunks.
    for chunk in padded.chunks(64) {
        // Create a 64-entry message schedule array of 32–bit words.
        let mut w = [0u32; 64];
        // The first 16 words are obtained directly from the chunk.
        for i in 0..16 {
            let j = i * 4;
            w[i] = ((chunk[j] as u32) << 24)
                 | ((chunk[j + 1] as u32) << 16)
                 | ((chunk[j + 2] as u32) << 8)
                 | ((chunk[j + 3] as u32));
        }
        // Extend the first 16 words into the remaining 48 words.
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7)
                   ^ w[i - 15].rotate_right(18)
                   ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17)
                   ^ w[i - 2].rotate_right(19)
                   ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                 .wrapping_add(s0)
                 .wrapping_add(w[i - 7])
                 .wrapping_add(s1);
        }

        // Initialize working variables to current hash value.
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        // Main compression function.
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value.
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    // Produce the final hash value (big–endian) as a 32–byte array.
    let mut hash = [0u8; 32];
    for (i, h_val) in [h0, h1, h2, h3, h4, h5, h6, h7].iter().enumerate() {
        hash[i * 4] = (h_val >> 24) as u8;
        hash[i * 4 + 1] = (h_val >> 16) as u8;
        hash[i * 4 + 2] = (h_val >> 8) as u8;
        hash[i * 4 + 3] = *h_val as u8;
    }
    hash
}
