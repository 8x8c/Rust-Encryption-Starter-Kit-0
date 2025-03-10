
# XOR-based Double One-Time Pad Encryption (`secure`)

## Overview
This is a secure and straightforward encryption tool built in Rust. It utilizes a **double XOR encryption** method inspired by the One-Time Pad (OTP)—the only encryption technique proven mathematically unbreakable when used correctly.

The encryption process applies two separate XOR encryption rounds, each secured by independent keys (`key.key` and `key1.key`) and random nonces. It also includes built-in file integrity checking using SHA-256 to detect any tampering.

## Why XOR Encryption?
XOR encryption is extremely simple yet highly secure if managed correctly. A properly implemented OTP system requires:

- Random keys at least as long as the plaintext.
- Single-use keys.

In practical usage, keys might be shorter and need reuse (wrapping). To protect against these limitations, this implementation uses **two layers** of XOR encryption with independent keys and unique nonces, greatly enhancing security.

## Encryption Process (Simplified)
Your file undergoes two rounds of XOR encryption:

### Round 1:
- A random 32-byte nonce (`nonce_layer1`) is generated.
- This nonce is XOR'd with the primary key (`key.key`) to produce a derived key.
- The plaintext is XOR-encrypted using this derived key.

### Round 2:
- Another random 32-byte nonce (`nonce_layer2`) is generated.
- This nonce is XOR'd with the secondary key (`key1.key`) to produce a second derived key.
- The intermediate ciphertext from Round 1 is XOR-encrypted again.

### Authentication:
- The final ciphertext is hashed with SHA-256.
- This hash is stored alongside the ciphertext to verify file integrity during decryption.

## File Structure:
Encrypted files are stored as follows:

```
[ nonce_layer1 (32 bytes) | nonce_layer2 (32 bytes) | SHA-256 hash (32 bytes) | ciphertext (remaining bytes) ]
```

## Usage Instructions:

### Encryption:
```bash
./secure E plaintext.txt encrypted.bin
```

### Decryption:
```bash
./secure D encrypted.bin decrypted.txt
```

Ensure the keys (`key.key` and `key1.key`) exist in your working directory.

## Security Analysis:

### Strengths:
- **Double-layer XOR encryption** significantly mitigates weaknesses from key reuse.
- **Independent random nonces** prevent cryptanalysis based on repeating patterns.
- **SHA-256 hashing** detects any file tampering or corruption immediately.
- **Simple and transparent**, greatly reducing the likelihood of implementation errors.

### Comparison to AES or ChaCha20:
- Under ideal OTP conditions (unique, random, single-use keys), this XOR encryption is **theoretically stronger** than AES or ChaCha20.
- Practically, when using wrapped keys, this double-layer XOR approach still offers security comparable to standard algorithms, with simplicity and transparency as major benefits.

## Recommendations for Maximum Security:
- Generate both keys (`key.key` and `key1.key`) using cryptographically secure methods.
- Minimize key reuse. Always use fresh, securely generated keys and nonces where possible.
- Keep keys secure and private, separate from ciphertext storage.

## Final Thoughts:
This implementation provides a strong balance between simplicity, security, and reliability—ideal for secure file encryption needs without the complexity and potential pitfalls of more complicated algorithms.

**Enjoy secure encrypting!**
