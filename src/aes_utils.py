import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32
NONCE_SIZE = 12


def generate_aes_key() -> bytes:
    """
    Generates a random AES-256 key.

    Returns:
        bytes: A 32-byte key for AES-256.
    """
    return os.urandom(AES_KEY_SIZE)


def encrypt_file_bytes(file_data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts file data using AES-GCM.

    AES-GCM provides both confidentiality and integrity.

    Parameters:
        file_data (bytes): File content to encrypt.
        key (bytes): AES key (32 bytes for AES-256).

    Returns:
        tuple[bytes, bytes]: nonce and ciphertext
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be 32 bytes for AES-256.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return nonce, ciphertext


def decrypt_file_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-GCM encrypted file data.

    Parameters:
        nonce (bytes): Nonce used during encryption.
        ciphertext (bytes): Encrypted file data.
        key (bytes): AES key used for decryption.

    Returns:
        bytes: Original decrypted file data
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be 32 bytes for AES-256.")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)