"""
Signature Utilities Module

This module handles:
- Digital signing using RSA private key
- Signature verification using RSA public key

In this project:
- RSA is used for authentication and integrity
- DH handles key exchange
- AES handles file encryption

Note:
The cryptography library hashes the message internally using SHA-256
before signing, so we do not hash manually.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Sign a message using RSA-PSS and SHA-256.

    Parameters:
    - private_key: sender's RSA private key
    - message: raw bytes to sign

    Returns:
    - signature bytes
    """
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(
    public_key: rsa.RSAPublicKey,
    message: bytes,
    signature: bytes
) -> bool:
    """
    Verify RSA-PSS signature.

    Parameters:
    - public_key: sender's RSA public key
    - message: original signed bytes
    - signature: signature to verify

    Returns:
    - True if valid
    - False if invalid
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_public_key_bytes(private_key: rsa.RSAPrivateKey, public_key_bytes: bytes) -> bytes:
    """
    Sign serialized public key bytes.

    Used to authenticate DH public keys.
    """
    return sign_message(private_key, public_key_bytes)


def verify_public_key_bytes(
    signer_public_key: rsa.RSAPublicKey,
    public_key_bytes: bytes,
    signature: bytes
) -> bool:
    """
    Verify signature on serialized public key bytes.

    Used to authenticate DH public keys before using them.
    """
    return verify_signature(signer_public_key, public_key_bytes, signature)