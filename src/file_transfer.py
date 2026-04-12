from aes_utils import generate_aes_key, encrypt_file_bytes, decrypt_file_bytes
from dh_utils import (
    generate_dh_key_pair, 
    serialize_public_key,
    deserialize_public_key,
    derive_shared_secret,
)
from signature_utils import sign_message, verify_signature


def secure_file_for_transfer_dh(
    file_data: bytes,
    sender_private_key,  # RSA private key for signing
    receiver_public_key_bytes,  # DH public key from receiver (bytes)
) -> dict:
    """
    Prepares a file for secure transfer using DH + RSA hybrid cryptography.
    
    Security flow:
    1. Sender generates ephemeral DH key pair
    2. Derive shared AES key using receiver's DH public key
    3. Encrypt file using AES-GCM with derived key
    4. Sign the full package using sender's RSA private key
    
    Note: AES key is NOT sent - both parties derive it independently.
    """
    # Generate ephemeral DH key pair for this session
    sender_dh_private, sender_dh_public, dh_params = generate_dh_key_pair()

    receiver_public_key = deserialize_public_key(receiver_public_key_bytes)
    
    # Derive shared AES key using receiver's DH public key
    aes_key = derive_shared_secret(sender_dh_private, receiver_public_key)
    
    # Encrypt file with AES-GCM using derived key
    nonce, ciphertext = encrypt_file_bytes(file_data, aes_key)
    
    # Serialize sender's DH public key to send to receiver
    sender_dh_public_bytes = serialize_public_key(sender_dh_public)
    
    # Build package bytes to sign (everything except signature)
    package_to_sign = nonce + ciphertext + sender_dh_public_bytes
    
    # Sign with sender's RSA private key
    signature = sign_message(sender_private_key, package_to_sign)
    
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "sender_dh_public_key": sender_dh_public_bytes,
        "signature": signature,
    }


def receive_secure_file_dh(
    package: dict,
    receiver_dh_private_key,  # Receiver's DH private key
    sender_public_key,  # Sender's RSA public key for verification
) -> bytes:
    """
    Receives and decrypts a secure file package using DH key exchange.
    """
    nonce = package["nonce"]
    ciphertext = package["ciphertext"]
    sender_dh_public_bytes = package["sender_dh_public_key"]
    signature = package["signature"]
    
    # Rebuild the package that was signed
    package_to_verify = nonce + ciphertext + sender_dh_public_bytes
    
    # Verify sender's RSA signature
    if not verify_signature(sender_public_key, package_to_verify, signature):
        raise ValueError("Signature verification failed.")
    
    sender_dh_public = deserialize_public_key(sender_dh_public_bytes)
    
    # Derive the same AES key using receiver's DH private key and sender's DH public key
    aes_key = derive_shared_secret(receiver_dh_private_key, sender_dh_public)
    
    # Decrypt file
    return decrypt_file_bytes(nonce, ciphertext, aes_key)