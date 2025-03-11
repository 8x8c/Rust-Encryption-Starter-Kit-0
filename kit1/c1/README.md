# c1 - Very simple, secure and reliable file encryption.


This app is made with 2 files. It has only 3 command functions. It is incredibly easy to feed the code to ai and have it change anything you want. 

c1 provides a straightforward and effective command-line tool for managing file encryption and decryption using robust cryptographic primitives available in Rust. Its modular design clearly separates key generation, encryption, and decryption operations, making the code easy to understand, maintain, and extend.

The key file is always named key.key and is expected to reside in the same directory as the executable. You have two options for key management: either generate key.key from a password (which produces a deterministic key using SHA3-256) or supply your own 256-bit (32-byte) key by creating a file named key.key in the executable’s directory. This approach ensures consistency and simplifies key handling across all operations.

The app utilizes xChaCha20-Poly1305 for encryption. This choice was made because xChaCha20-Poly1305  is less error-prone to implement in a custom application than AES, while still offering a comparable level of security. Numerous comparisons between ChaCha20 and AES highlight that both ciphers are excellent; however, xChaCha20-Poly1305  is often simpler and more reliable for “homemade” projects. Additionally, it does not require specialized hardware to achieve optimal performance, unlike AES. For more in-depth analysis, please refer to the /docs directory in this repo. I put the docs in html form, just view the file from a browser.

While c1 is ideal for personal and small-scale projects, it is important to recognize that professional, production-grade encryption applications are generally superior in terms of auditing, testing, and handling edge cases. Nonetheless, c1 offers a practical, secure, and user-friendly solution for everyday encryption needs. 

# Make an optional deterministic key
./c1 -k adelia  

will make key.key - the key will be the same every time you use the password "adelia". You can use any password to make a specific key. Or you can make a key.key file with your own key. This is very versatile. 

# Encrypt a file 
./c1 -e plain.txt encrypted.dat  

encrypts plain.txt to a file called encrypted.dat 

# Decrypt a file 
./c1 -d encrypted.dat decrypted.txt  

decrypts encrypted.dat to a file called decrypted.txt 

# Tampering 

If even one byte of the encrypted file is changed, it will not be able to be decrypted. It will return --- Error: "Decryption failed: Error"  

# notes
See /docs for more info. 

This version does not encrypt in chunks. MAKE SURE you have enough ram for the size of file you need to encrypt. For example, to encrypt a 5 gb file, you would need 10 gb of free ram. With a fast cpu and a 64 gb ddr5 you can encrypt just about anything. On a small laptop with 4gb ram, you would have to see how much free ram you have before encrypting very large files. Chunk based processing could handle any filesize with less ram- but it also ads more complexity. This app in its current form is made to be as simple, secure and reliable as possible, so i did not implement chunk based processing. c1Cha20Poly1305 does very well as long as it has enough ram for very large files. 






