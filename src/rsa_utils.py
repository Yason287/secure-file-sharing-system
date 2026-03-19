# This module handles RSA operations:
# - Key generation and storage
# - Encryption/decryption of AES session keys
# - Used as part of hybrid cryptography with AES

from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_rsa_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key: rsa.RSAPrivateKey, file_path: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    path.write_bytes(pem_data)


def save_public_key(public_key: rsa.RSAPublicKey, file_path: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    path.write_bytes(pem_data)


def load_private_key(file_path: str) -> rsa.RSAPrivateKey:
    pem_data = Path(file_path).read_bytes()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )
    return private_key


def load_public_key(file_path: str) -> rsa.RSAPublicKey:
    pem_data = Path(file_path).read_bytes()

    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def encrypt_with_public_key(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_with_private_key(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def encrypt_aes_key(public_key: rsa.RSAPublicKey, aes_key: bytes) -> bytes:
    """
    Encrypts an AES session key using the receiver's RSA public key.

    This function is part of the hybrid cryptography workflow:
    - AES is used to encrypt large files (fast and efficient)
    - RSA is used only to securely transmit the AES key

    Why do we do this?
    RSA is slow and has size limitations, so instead of encrypting the entire file
    with RSA, we encrypt only the AES key. The AES key is then used to encrypt
    the actual file.

    Parameters:
    - public_key (rsa.RSAPublicKey):
        The receiver's RSA public key. Anyone can use this key to encrypt data,
        but only the receiver can decrypt it using their private key.

    - aes_key (bytes):
        The symmetric AES key (typically 32 bytes for AES-256) that will be used
        to encrypt the file.

    Returns:
    - bytes:
        The AES key encrypted with RSA. This encrypted key can be safely transmitted
        over an insecure channel.
    """
    return encrypt_with_public_key(public_key, aes_key)


def decrypt_aes_key(private_key: rsa.RSAPrivateKey, encrypted_aes_key: bytes) -> bytes:
    """
    Decrypts an AES session key using the receiver's RSA private key.

    This is the reverse operation of encrypt_aes_key(). After receiving the encrypted
    AES key, the receiver uses their private key to recover the original AES key.

    Only the owner of the private key can perform this operation, which ensures
    confidentiality of the AES key.

    Parameters:
    - private_key (rsa.RSAPrivateKey):
        The receiver's RSA private key. This key must be kept secret.

    - encrypted_aes_key (bytes):
        The AES key that was previously encrypted using the receiver's public key.

    Returns:
    - bytes:
        The original decrypted AES key, which can now be used to decrypt the file.
    """
    return decrypt_with_private_key(private_key, encrypted_aes_key)
