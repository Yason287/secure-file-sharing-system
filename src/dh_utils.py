from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os

_DEFAULT_PARAMETERS = None

def get_dh_parameters():
    global _DEFAULT_PARAMETERS
    if _DEFAULT_PARAMETERS is None:
        _DEFAULT_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)
    return _DEFAULT_PARAMETERS

def generate_dh_key_pair(parameters=None):
    if parameters is None:
        parameters = get_dh_parameters() 
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters

def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes: bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Derives shared secret using DH key exchange.
    
    Returns:
        bytes: 32-byte shared secret to be used as AES key
    """
    shared_secret = private_key.exchange(peer_public_key)
    
    # Use HKDF to derive a strong 32-byte AES key from the shared secret

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=None,
        info=b'aes-gcm-file-encryption'
    ).derive(shared_secret)
    
    return derived_key

def derive_shared_secret_with_public_bytes(
    private_key, 
    peer_public_key_bytes: bytes
) -> bytes:
    """Derives shared secret when peer's public key is in bytes format"""
    peer_public_key = deserialize_public_key(peer_public_key_bytes)
    return derive_shared_secret(private_key, peer_public_key)

    """Serializes DH public key to bytes for transmission"""
    """Deserializes DH public key from bytes"""
