# secure-file-sharing-system

INSE 6110 course project: Secure File Sharing System with RSA authentication, AES encryption, and integrity verification.

## 🔐 RSA Module – Key Exchange and Authentication

This project implements a secure file sharing system using hybrid cryptography, combining RSA (asymmetric encryption) and AES (symmetric encryption).

The RSA module is responsible for:

- Generating RSA key pairs (public/private keys)
- Securely exchanging AES session keys
- Providing authentication using digital signatures

### 🔑 Key Exchange (RSA)

RSA is used to securely transmit the AES session key between users.

Instead of encrypting large files directly with RSA (which is inefficient and size-limited), the system:

1. Generates a random AES key (e.g., 256-bit)
2. Encrypts the AES key using the receiver’s RSA public key
3. Sends the encrypted AES key along with the encrypted file
4. The receiver decrypts the AES key using their RSA private key

### ✍️ Authentication (Digital Signatures)

To guarantee authenticity and integrity, the sender signs data using their RSA private key.

- The sender creates a digital signature of the message or AES key
- The receiver verifies the signature using the sender’s public key

This ensures that:
- The message was not modified (integrity)
- The sender is authenticated (authenticity)

### 🔄 Hybrid Cryptography Workflow

1. Generate AES key  
2. Encrypt file using AES  
3. Encrypt AES key using RSA (receiver’s public key)  
4. Sign the AES key or file using RSA (sender’s private key)  
5. Transmit encrypted file + encrypted AES key + signature  
6. Receiver:
   - Decrypts AES key using RSA private key  
   - Verifies signature using sender’s public key  
   - Decrypts file using AES  

### ⚙️ Technologies Used

- Python  
- cryptography library  
- RSA (2048-bit, OAEP padding)  
- AES (to be integrated)  
- SHA-256 (for hashing and signatures)
