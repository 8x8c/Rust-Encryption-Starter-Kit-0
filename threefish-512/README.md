# Threefish CLI (Rust)


A simple command-line application for encrypting and decrypting files using the Threefish-512 block cipher in Rust. This is for educational/demo purposes and uses a naive “ECB-like” approach. Do not use this in production without applying a more secure block-cipher mode and best practices in key management, padding, and authentication.

# Commands
to encrypt --  ./three  plain.txt cypher.txt
to decrypt -- ./three  cypher.txt decrypted.txt 

that is all the commands- this is meant to be simple. 


# Features
Threefish-512 encryption/decryption.

Naive ECB-like mode by splitting files into 64-byte blocks.

Hardcoded 512-bit key and 128-bit tweak (for testing/demo).

Simple CLI with two subcommands: encrypt and decrypt.

# Security Disclaimer

ECB Mode: This code splits the file into 64-byte blocks and encrypts each block independently. This can leak patterns in data. A more secure mode (e.g., XTS, CTR, or an authenticated mode like GCM) should be used for real-world encryption tasks.

Hardcoded Key/Tweak: The key and tweak are not derived or protected. Storing cryptographic keys in source code is insecure in production.

No Integrity Check: There is no authentication or HMAC to detect tampering.

Memory Usage: The code reads entire files into memory. For large files, you’d want to process data in streaming/chunked fashion.
