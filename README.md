# secure-file-sharing-system

INSE 6110 course project: Secure File Sharing System using hybrid cryptography (Diffie-Hellman + AES + Digital Signatures).

---

## Overview

This project implements a secure file sharing system using modern hybrid cryptography:

- **Diffie-Hellman (DH)** for secure key exchange  
- **AES-GCM (AES-256)** for efficient and authenticated file encryption  
- **RSA Digital Signatures (RSA-PSS + SHA-256)** for authentication and integrity  

The system ensures:
- Confidentiality
- Integrity
- Authentication
- Protection against tampering attacks

---

## Updated Cryptographic Design

This project follows a **secure and realistic design**:

- RSA is **NOT used for encryption anymore**
- Diffie-Hellman is used to establish a shared secret
- AES key is derived from DH using **HKDF-SHA256**
- RSA is used **only for digital signatures**

---

## Secure Workflow (Step-by-Step)

### Bob (Receiver)

1. Generates:
   - RSA key pair (for signatures)
   - DH key pair

2. Signs his **DH public key** using his RSA private key

3. Sends to Alice:
   - DH public key (serialized)
   - Signature of DH public key

---

### Alice (Sender)

1. Verifies Bob’s DH public key signature  
   → Prevents Man-in-the-Middle attacks  

2. Generates an **ephemeral DH key pair**

3. Computes shared secret:
   - Using her private DH key
   - And Bob’s public DH key

4. Derives AES-256 key using:
   - HKDF with SHA-256

5. Encrypts file using AES-GCM:
   - Produces: ciphertext + nonce

6. Creates a digital signature over:
   - ciphertext
   - nonce
   - her DH public key

7. Sends:
   - ciphertext
   - nonce
   - Alice’s DH public key
   - signature

---

### Bob (Receiver)

1. Verifies Alice’s signature  

2. Computes shared secret:
   - Using his DH private key
   - And Alice’s DH public key  

3. Derives same AES key (HKDF)

4. Decrypts file using AES-GCM  

---

## Security Properties

- **Confidentiality** → AES-GCM encryption  
- **Integrity** → AES-GCM authentication + RSA signature  
- **Authentication** → RSA signatures  
- **Forward secrecy** → Alice uses ephemeral DH keys  
- **Tampering detection**:
  - Modified ciphertext → detected
  - Modified DH public key → detected  

---

## Project Structure
