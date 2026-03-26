from aes_utils import generate_aes_key, encrypt_file_bytes, decrypt_file_bytes
from rsa_utils import encrypt_aes_key, decrypt_aes_key
from signature_utils import sign_message, verify_signature


def secure_file_for_transfer(
    file_data: bytes,
    sender_private_key,
    receiver_public_key
) -> dict:
    """
    Prepares a file for secure transfer.

    Steps:
    1. Generate AES key
    2. Encrypt file with AES
    3. Encrypt AES key with receiver's RSA public key
    4. Sign the AES key with sender's private key
    """
    aes_key = generate_aes_key()
    nonce, ciphertext = encrypt_file_bytes(file_data, aes_key)
    encrypted_aes_key = encrypt_aes_key(receiver_public_key, aes_key)
    signature = sign_message(sender_private_key, aes_key)

    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "encrypted_aes_key": encrypted_aes_key,
        "signature": signature,
    }


def receive_secure_file(
    package: dict,
    receiver_private_key,
    sender_public_key
) -> bytes:
    """
    Receives and decrypts a secure file package.

    Steps:
    1. Decrypt AES key using receiver's private key
    2. Verify sender's signature
    3. Decrypt file using AES
    """
    encrypted_aes_key = package["encrypted_aes_key"]
    nonce = package["nonce"]
    ciphertext = package["ciphertext"]
    signature = package["signature"]

    aes_key = decrypt_aes_key(receiver_private_key, encrypted_aes_key)

    if not verify_signature(sender_public_key, aes_key, signature):
        raise ValueError("Signature verification failed.")

    return decrypt_file_bytes(nonce, ciphertext, aes_key)
