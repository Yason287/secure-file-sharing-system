"""
RSA Utilities Module

This module handles:
- RSA key generation
- Saving and loading RSA keys

In the current design:
- DH is used for key exchange
- RSA is used only for digital signatures
"""

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_rsa_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA key pair.

    Returns:
    - private key
    - public key
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key: rsa.RSAPrivateKey, file_path: str) -> None:
    """
    Save RSA private key to a PEM file.

    Note:
    - For this prototype, the private key is not password-protected
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    path.write_bytes(pem_data)


def save_public_key(public_key: rsa.RSAPublicKey, file_path: str) -> None:
    """
    Save RSA public key to a PEM file.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    path.write_bytes(pem_data)


def load_private_key(file_path: str) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from a PEM file.
    """
    pem_data = Path(file_path).read_bytes()
    return serialization.load_pem_private_key(pem_data, password=None)


def load_public_key(file_path: str) -> rsa.RSAPublicKey:
    """
    Load RSA public key from a PEM file.
    """
    pem_data = Path(file_path).read_bytes()
    return serialization.load_pem_public_key(pem_data)