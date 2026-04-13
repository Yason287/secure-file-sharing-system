"""
Secure File Transfer Module

This module handles:
- Secure file packaging for transfer
- Receiver-side verification and decryption

Design:
- Bob authenticates his DH public key to Alice using RSA signature
- Alice verifies Bob's DH public key before using it
- Alice creates an ephemeral DH key pair using Bob's DH parameters
- Both derive the same AES key from DH + HKDF
- Alice encrypts file with AES-GCM
- Alice signs the full package with RSA
- Bob verifies the package signature before decrypting
"""

from aes_utils import encrypt_file_bytes, decrypt_file_bytes
from dh_utils import (
    generate_dh_key_pair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_secret,
)
from signature_utils import (
    sign_message,
    verify_signature,
    verify_public_key_bytes,
)


def secure_file_for_transfer_dh(
    file_data: bytes,
    sender_private_key,                # Alice RSA private key
    receiver_public_key_bytes: bytes,  # Bob DH public key bytes
    receiver_public_key_signature: bytes,  # Bob RSA signature on his DH public key
    receiver_signing_public_key,       # Bob RSA public key
) -> dict:
    """
    Prepare a secure package for transfer.

    Steps:
    1. Verify Bob's DH public key using Bob's RSA public key
    2. Create Alice ephemeral DH key pair using Bob's DH parameters
    3. Derive shared AES key
    4. Encrypt file with AES-GCM
    5. Sign the full package using Alice's RSA private key

    Returns:
    - package dictionary
    """

    # Authenticate Bob's DH public key before using it
    if not verify_public_key_bytes(
        receiver_signing_public_key,
        receiver_public_key_bytes,
        receiver_public_key_signature,
    ):
        raise ValueError("Receiver DH public key authentication failed.")

    # Load Bob's DH public key
    receiver_public_key = deserialize_public_key(receiver_public_key_bytes)

    # IMPORTANT:
    # Alice must generate her DH key pair using Bob's DH parameters
    receiver_parameters = receiver_public_key.parameters()
    sender_dh_private, sender_dh_public, _ = generate_dh_key_pair(receiver_parameters)

    # Derive AES key from shared secret
    aes_key = derive_shared_secret(sender_dh_private, receiver_public_key)

    # Encrypt file using AES-GCM
    nonce, ciphertext = encrypt_file_bytes(file_data, aes_key)

    # Send Alice's ephemeral DH public key to Bob
    sender_dh_public_bytes = serialize_public_key(sender_dh_public)

    # Sign the full package
    package_to_sign = nonce + ciphertext + sender_dh_public_bytes
    signature = sign_message(sender_private_key, package_to_sign)

    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "sender_dh_public_key": sender_dh_public_bytes,
        "signature": signature,
    }


def receive_secure_file_dh(
    package: dict,
    receiver_dh_private_key,  # Bob DH private key
    sender_public_key,        # Alice RSA public key
) -> bytes:
    """
    Verify and decrypt received package.

    Steps:
    1. Verify Alice's RSA signature on the package
    2. Recover Alice's DH public key
    3. Derive AES key using Bob's DH private key
    4. Decrypt file with AES-GCM

    Returns:
    - decrypted file bytes
    """
    nonce = package["nonce"]
    ciphertext = package["ciphertext"]
    sender_dh_public_bytes = package["sender_dh_public_key"]
    signature = package["signature"]

    # Rebuild package bytes exactly as signed
    package_to_verify = nonce + ciphertext + sender_dh_public_bytes

    # Verify Alice's RSA signature
    if not verify_signature(sender_public_key, package_to_verify, signature):
        raise ValueError("Signature verification failed.")

    # Recover Alice's DH public key
    sender_dh_public = deserialize_public_key(sender_dh_public_bytes)

    # Derive same AES key from DH shared secret
    aes_key = derive_shared_secret(receiver_dh_private_key, sender_dh_public)

    # Decrypt file
    return decrypt_file_bytes(nonce, ciphertext, aes_key)