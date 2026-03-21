import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32
NONCE_SIZE = 12


def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_SIZE)


def encrypt_file_bytes(file_data: bytes, key: bytes):
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return nonce, ciphertext


def decrypt_file_bytes(nonce: bytes, ciphertext: bytes, key: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)