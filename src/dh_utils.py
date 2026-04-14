"""
Diffie-Hellman Utilities Module

This module handles:
- DH parameter generation
- DH key pair generation
- Public key serialization/deserialization
- Shared secret derivation
- HKDF-based AES key derivation

In this project:
- DH is used for key agreement
- HKDF derives a 32-byte AES-256 key from the shared secret
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

_DEFAULT_PARAMETERS = None


def get_dh_parameters():
    """
    Generate and cache default DH parameters.

    Note:
    Parameter generation is expensive, so we reuse them.
    """
    global _DEFAULT_PARAMETERS
    if _DEFAULT_PARAMETERS is None:
        _DEFAULT_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)
    return _DEFAULT_PARAMETERS


def generate_dh_key_pair(parameters=None):
    """
    Generate a DH key pair.

    Parameters:
    - parameters: DH parameters to use
      If None, default cached parameters are used.

    Returns:
    - private key
    - public key
    - parameters
    """
    if parameters is None:
        parameters = get_dh_parameters()

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters


def serialize_public_key(public_key) -> bytes:
    """
    Serialize public key to PEM bytes for transmission.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key_bytes: bytes):
    """
    Deserialize PEM bytes back into a public key object.
    """
    return serialization.load_pem_public_key(public_key_bytes)


def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Derive AES-256 key from DH shared secret using HKDF-SHA256.

    Parameters:
    - private_key: local DH private key
    - peer_public_key: peer's DH public key

    Returns:
    - 32-byte AES key
    """
    shared_secret = private_key.exchange(peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'aes-gcm-file-encryption'
    ).derive(shared_secret)

    return derived_key


def derive_shared_secret_with_public_bytes(private_key, peer_public_key_bytes: bytes) -> bytes:
    """
    Derive AES key when peer public key is received as bytes.
    """
    peer_public_key = deserialize_public_key(peer_public_key_bytes)
    return derive_shared_secret(private_key, peer_public_key)