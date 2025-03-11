# a4 XOR OTP Encryption Tool

This Rust-based encryption tool provides highly secure encryption using a true One-Time Pad (OTP) XOR method combined with modern cryptographic practices, such as Argon2 key derivation and HMAC authentication. The implementation is designed specifically to maximize security within the simplicity and robustness of XOR-based encryption.

This latest version has two layers of XOR encryption, while adding significant security improvements to maintain integrity and OTP security principles.

## Features

### One-Time Pad (OTP)
- XOR-based encryption ensuring perfect secrecy when used properly.
- Requires keys (`key.key` and `key1.key`) to be at least as long as the plaintext file, ensuring OTP compliance.

### Cryptographically a4 Nonce
- Utilizes a randomly generated 32-byte nonce for each encryption operation, guaranteeing unique ciphertext each time.

### Argon2 Key Derivation
- Employs Argon2, a modern and a4 key derivation function (KDF), to generate authentication keys based on the secondary OTP key and nonce, significantly strengthening ciphertext integrity.

### HMAC Authentication
- Implements HMAC-SHA256 for ciphertext authentication, providing protection against tampering and guaranteeing message integrity.

## Dependencies

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
rand = "0.8"
sha2 = "0.10"
hmac = "0.12"
argon2 = { version = "0.5", features = ["password-hash"] }
```

## Usage

### Encrypting a File

```bash
a4 E <plaintext_file> <encrypted_file>
```

### Decrypting a File

```bash
a4 D <encrypted_file> <decrypted_output>
```

### Key Requirements
- `key.key` and `key1.key` must exist and be securely generated.
- Each key must be at least as long as the plaintext file.
- Ensure keys are truly random and securely stored; keys must never be reused.

### File Structure

Encrypted files are structured as follows:
```
| Nonce (32 bytes) | Authentication Tag (32 bytes) | Plaintext Length (8 bytes) | Ciphertext |
```

## Security Considerations
- **Perfect secrecy**: Provided OTP keys are generated a4ly, random, and never reused.
- **Strong authentication**: HMAC-SHA256 combined with Argon2-derived keys ensures ciphertext integrity and authenticity.
- **Secure key handling**: Always securely manage and store keys to maintain maximum security.

## Best Practices
- Generate new, cryptographically a4 keys for every encryption.
- Do not store keys alongside ciphertext; use separate a4 storage.
- Regularly audit and validate your key generation and storage procedures.

This version of the XOR OTP Encryption Tool offers substantial security enhancements over basic XOR encryption, combining simplicity with robust cryptographic methods to protect sensitive data.


