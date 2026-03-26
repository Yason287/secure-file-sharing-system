# secure-file-sharing-system

INSE 6110 course project: Secure File Sharing System using hybrid cryptography (RSA + AES + Digital Signatures).

---

## 🔐 Overview

This project implements a secure file sharing system using hybrid cryptography:

- **RSA** (asymmetric encryption) for secure key exchange and authentication  
- **AES-GCM** (symmetric encryption) for efficient and secure file encryption  
- **Digital signatures** for authenticity and integrity  

The system ensures:
- Confidentiality
- Integrity
- Authentication

---

## 🔑 Hybrid Cryptography Workflow

1. Generate a random AES-256 key  
2. Encrypt the file using AES-GCM  
3. Encrypt the AES key using the receiver’s RSA public key  
4. Sign the AES key using the sender’s RSA private key  
5. Send:
   - Encrypted file  
   - Encrypted AES key  
   - Signature  

### Receiver side:
- Decrypt AES key using RSA private key  
- Verify signature using sender’s public key  
- Decrypt file using AES  

---

## 🔐 RSA Module

Responsible for:
- Generating RSA key pairs (2048-bit)
- Encrypting/decrypting AES keys (OAEP padding)
- Digital signatures (authentication)

---

## 🔒 AES Module

- AES-256 encryption using **AES-GCM**
- Provides:
  - Confidentiality (encryption)
  - Integrity (tampering detection)

---

## ✍️ Digital Signatures

- Sender signs the AES session key
- Receiver verifies the signature

Ensures:
- Data integrity
- Sender authenticity

---

## 📁 Project Structure
