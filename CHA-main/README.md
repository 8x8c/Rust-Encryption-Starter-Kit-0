# CHA- One page encryption tools made with Rust. 


There have been numerous encryption apps that were touted as being a helper of PRIVACY- but in reality they were a form of malware. None of that crap nonsense here. CHA is a bunch of individual tools with one page codebases- extremely easy to audit or modify. They are all coded with Rust- which is objectively superior to most other langs.  THIS REPO IS MAINTAINED, and input from the community is welcome. It is not the year 1920 tho- i do not need a "community"!  I will keep each app to a single page (main.rs) , and have Ai audit it often. 

Again, it's not 1920 any more. Apps that do simple tasks and have over 100 files are hard for Ai to monitor and audit. They are hard for the user to run, with so many commands. To make a NO BS, NO NONSENSE app, it should have a tiny codebase and be simple to operate. The best apps should be coded in a memory safe lang like Rust- which is FAR superior to older, more dangerous langs. 


Some CHA applications use the XChaCha20-Poly1305 algorithm for encryption. In Chakey, the key is loaded from a file, while in Chapass the key is derived from a password using Argon2. However, the actual encryption/decryption process in both apps is handled by XChaCha20-Poly1305, ensuring authenticated encryption with a random 24-byte nonce.

Chaaes is an AES tool. I think Ai has to get WAY better in order to handle properly making AES apps. In contrast, XChaCha20-Poly1305 is MUCH SIMPLER to implemnent than AES. To be sure, Chaaes is the most complicated encryption tool in the CHA group- so it is the hardest to audit. 

Chaotp is a One Time Pad app. Read the docs. Besides being the ONLY uncrackable encryption known- it is so simple that a half a page of any lang can do it. It will overwrite the input file or it will encrypt the input file to another file. 


