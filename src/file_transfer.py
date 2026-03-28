from aes_utils import generate_aes_key, encrypt_file_bytes, decrypt_file_bytes
from rsa_utils import encrypt_aes_key, decrypt_aes_key
from signature_utils import sign_message, verify_signature


def secure_file_for_transfer(
    file_data: bytes,
    sender_private_key,
    receiver_public_key
) -> dict:
    """
    Prepares a file for secure transfer using hybrid cryptography.

    Security flow:
    1. Generate a random AES session key.
    2. Encrypt the file data using AES-GCM.
    3. Encrypt the AES key using the receiver's RSA public key.
    4. Build the package contents.
    5. Sign the full package using the sender's RSA private key.

    Why sign the full package?
    This protects all critical transmitted values:
    - nonce
    - ciphertext
    - encrypted AES key

    If any of these values are modified, signature verification will fail.

    Parameters:
    - file_data (bytes): raw file content
    - sender_private_key: sender's RSA private key
    - receiver_public_key: receiver's RSA public key

    Returns:
    - dict: secure package containing encrypted file data and signature
    """
    aes_key = generate_aes_key()

    # Encrypt file with AES-GCM
    nonce, ciphertext = encrypt_file_bytes(file_data, aes_key)

    # Encrypt AES key with receiver's RSA public key
    encrypted_aes_key = encrypt_aes_key(receiver_public_key, aes_key)

    # Build package bytes to sign
    package_to_sign = nonce + ciphertext + encrypted_aes_key

    # Sign the full package
    signature = sign_message(sender_private_key, package_to_sign)

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

    Security flow:
    1. Extract package components.
    2. Rebuild the signed package.
    3. Verify sender's signature on the full package.
    4. Decrypt AES key using receiver's RSA private key.
    5. Decrypt file using recovered AES key.

    Parameters:
    - package (dict): package returned by secure_file_for_transfer()
    - receiver_private_key: receiver's RSA private key
    - sender_public_key: sender's RSA public key

    Returns:
    - bytes: original decrypted file contents

    Raises:
    - ValueError: if signature verification fails
    """
    nonce = package["nonce"]
    ciphertext = package["ciphertext"]
    encrypted_aes_key = package["encrypted_aes_key"]
    signature = package["signature"]

    # Rebuild the exact package that was signed
    package_to_verify = nonce + ciphertext + encrypted_aes_key

    # Verify sender's signature before decrypting
    if not verify_signature(sender_public_key, package_to_verify, signature):
        raise ValueError("Signature verification failed.")

    # Recover AES key using receiver's private key
    aes_key = decrypt_aes_key(receiver_private_key, encrypted_aes_key)

    # Decrypt file using the recovered AES key
    return decrypt_file_bytes(nonce, ciphertext, aes_key)