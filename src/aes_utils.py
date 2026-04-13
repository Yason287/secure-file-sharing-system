"""
AES Utilities Module

This module handles:
- AES-GCM file encryption


In the current design:
- The AES key is NOT generated separately for transport
- It is derived from Diffie-Hellman (DH) + HKDF
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32   # 32 bytes = AES-256
NONCE_SIZE = 12     # Recommended nonce size for GCM


def encrypt_file_bytes(file_data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt file data using AES-GCM.

    Parameters:
    - file_data: raw file bytes
    - key: 32-byte AES key derived from DH

    Returns:
    - tuple:
        nonce, ciphertext

    Security:
    - AES-GCM provides confidentiality and integrity
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be 32 bytes for AES-256.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return nonce, ciphertext


def decrypt_file_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-GCM encrypted file data.

    Parameters:
    - nonce: nonce used during encryption
    - ciphertext: encrypted file bytes
    - key: 32-byte AES key

    Returns:
    - original plaintext bytes

    Raises:
    - Exception if authentication fails or ciphertext is tampered with
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be 32 bytes for AES-256.")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)