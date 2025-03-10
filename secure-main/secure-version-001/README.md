# XOR-Based One-Time Pad (OTP) Encryption Application

This application provides a simple, secure, and reliable encryption and decryption mechanism using XOR-based encryption combined with a one-time pad (OTP) method. By incorporating additional security layers and authentication measures, the app mitigates common vulnerabilities associated with traditional XOR encryption.

---

## 🛠️ Usage

To use the application, you execute it via the command line:

### Encryption
```bash
./secure E <input_file> <output_file>
```

### Decryption
```bash
./secure D <encrypted_file> <output_file>
```

### Requirements

- You must provide a file named `key.key`.
- The key can be shorter than the plaintext file. In such cases, the key will wrap automatically.
- It’s highly recommended, for absolute security, to ensure the key is:
  - At least as long as the plaintext file.
  - Randomly generated.
  - Used only once (never reused).

## How It Works (Detailed)

This application implements **XOR encryption**, enhanced to mitigate common vulnerabilities inherent in simple XOR-based methods:

1. **Nonce Generation**:  
   - A random 32-byte "nonce" (number used once) is created during encryption. This ensures unique ciphertext each time, even when encrypting the same plaintext with the same key.

2. **Double XOR Encryption**:
   - The plaintext data is first XORed with a combination of the provided key and the nonce.
   - A second random nonce (as long as the plaintext) is generated and XORed again with the intermediate ciphertext to further obscure patterns and strengthen encryption, especially when the key wraps.

2. **Authentication (Integrity Checking)**:
   - A SHA-256 hash of the final ciphertext is computed and stored alongside the ciphertext.
   - On decryption, the hash is recalculated and compared with the stored hash to verify integrity. If the file has been tampered with, the program alerts the user.

### File Structure

Encrypted files have the following internal structure:

```
[ nonce (32 bytes) | second_nonce (plaintext length) | hash (32 bytes) | ciphertext (plaintext length) ]
```

- **Nonce** ensures ciphertext uniqueness even with the same plaintext and key.
- **Second Nonce** adds additional security for wrapped or reused keys.
- **Hash** ensures integrity, immediately alerting you if the encrypted file was tampered with.

## Security Strengths and Considerations

- **Perfect Secrecy (OTP)**:  
  When used correctly (random key, at least as long as plaintext, never reused), the XOR method becomes mathematically proven to provide **perfect secrecy**, stronger than even AES or ChaCha20.

- **Security for Practical Use (wrapped keys)**:
  The double-layer XOR with random nonces makes this method exceptionally secure even if the key is shorter and wraps, dramatically mitigating risks associated with repeated keys.

- **Simplicity & Reliability**:
  The XOR method has fewer moving parts than algorithms like AES or ChaCha20. Fewer complexities typically mean fewer opportunities for implementation mistakes, contributing significantly to reliability and minimizing the potential for security vulnerabilities.

## Best Practices for Maximum Security

- **Generate Truly Random Keys**:
  Always generate your key from a cryptographically secure source.

- **Avoid Key Reuse**:
  For absolute security, do not reuse your keys.

- **Securely Manage Keys**:
  Keep your keys confidential and destroy them securely after use if required.

## Conclusion

This encryption tool provides a straightforward yet robust encryption method. Its simplicity means fewer potential implementation errors, and when used correctly (true OTP conditions), it guarantees **perfect secrecy**. Even under less-than-ideal circumstances, the double XOR method provides a highly secure encryption method suitable for practical scenarios where simplicity and security matter.


