# secure-file-sharing-system

INSE 6110 course project: Secure File Sharing System using hybrid cryptography (RSA + AES + Digital Signatures).



##  Overview

This project implements a secure file sharing system using hybrid cryptography:

- **RSA** (asymmetric encryption) for secure key exchange and authentication  
- **AES-GCM** (symmetric encryption) for efficient and secure file encryption  
- **Digital signatures** for authenticity and integrity  

The system ensures:
- Confidentiality
- Integrity
- Authentication



##  Hybrid Cryptography Workflow

1. Generate a random AES-256 key  
2. Encrypt the file using AES-GCM  
3. Encrypt the AES key using the receiver’s RSA public key  
4. Create a digital signature over:
   - nonce  
   - ciphertext  
   - encrypted AES key  
5. Send:
   - Encrypted file (ciphertext + nonce)  
   - Encrypted AES key  
   - Signature  

### Receiver side:
- Verify the signature using the sender’s public key  
- Decrypt AES key using RSA private key  
- Decrypt file using AES  



##  RSA Module

Responsible for:
- Generating RSA key pairs (2048-bit)
- Encrypting/decrypting AES keys (OAEP padding)
- Digital signatures (RSA-PSS with SHA-256)



##  AES Module

- AES-256 encryption using **AES-GCM**
- Provides:
  - Confidentiality (encryption)
  - Integrity (tampering detection)



##  Digital Signatures

- The sender signs the full encrypted package:
  - nonce + ciphertext + encrypted AES key  
- The receiver verifies the signature before decryption  

Ensures:
- Data integrity
- Sender authenticity



##  Testing

The system was tested with multiple file types:
- Text file (`sample.txt`)
- JSON file (`data.json`)

Results:
- Decryption output matches original input  
- Tampering detection successfully rejects modified data  



##  How to Run

1. Place a file inside the `input/` folder (e.g., `sample.txt` or `data.json`)  

2. Select the test case in `main.py`:
```python
# ==== TEST CASE 1: TEXT FILE ====
input_file_path = Path("input/sample.txt")

# ==== TEST CASE 2: JSON FILE ====
# input_file_path = Path("input/data.json")
