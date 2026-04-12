from pathlib import Path
from rsa_utils import (
    generate_rsa_key_pair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)
from dh_utils import generate_dh_key_pair, serialize_public_key
from file_transfer import secure_file_for_transfer_dh, receive_secure_file_dh


def main():
    # Setup directories
    Path("input").mkdir(exist_ok=True)
    Path("output").mkdir(exist_ok=True)
    Path("keys").mkdir(exist_ok=True)
    
    # Create test file
    input_file_path = Path("input/sample.txt")
    if not input_file_path.exists():
        input_file_path.write_text("This is a test file for secure transfer.", encoding="utf-8")
    
    # ===== RSA KEYS (for signatures only) =====
    # Alice (sender) RSA key pair for signing
    alice_private_key, alice_public_key = generate_rsa_key_pair()
    save_private_key(alice_private_key, "keys/alice_private.pem")
    save_public_key(alice_public_key, "keys/alice_public.pem")
    
    # ===== DH KEYS (for key exchange) =====
    # Bob (receiver) generates a long-term DH key pair
    bob_dh_private, bob_dh_public, dh_params = generate_dh_key_pair()
    
    # Bob shares his DH public key with Alice (in practice, via a key server or certificate)
    bob_dh_public_bytes = serialize_public_key(bob_dh_public)
    
    # Save Bob's DH public key for later use
    Path("keys/bob_dh_public.pem").write_bytes(bob_dh_public_bytes)
    
    # Load keys
    loaded_alice_private = load_private_key("keys/alice_private.pem")
    loaded_alice_public = load_public_key("keys/alice_public.pem")
    
    # Read file
    file_data = input_file_path.read_bytes()
    
    print("\n=== Secure File Sharing Demo (DH + RSA Signatures) ===")
    print("Input file:", input_file_path)
    
    # Alice secures the file for Bob using DH key exchange
    package = secure_file_for_transfer_dh(
        file_data=file_data,
        sender_private_key=loaded_alice_private,
        receiver_public_key_bytes=bob_dh_public_bytes,  # Bob's DH public key
    )
    
    # Bob receives and decrypts
    decrypted_file = receive_secure_file_dh(
        package=package,
        receiver_dh_private_key=bob_dh_private,
        sender_public_key=loaded_alice_public,
    )
    
    # Verify
    output_file_path = Path("output/decrypted_sample.txt")
    output_file_path.write_bytes(decrypted_file)
    
    print("Transfer successful:", file_data == decrypted_file)
    
    # Tampering test (same as before)
    print("\n=== Tampering Test ===")
    tampered_package = package.copy()
    tampered_ciphertext = bytearray(package["ciphertext"])
    tampered_ciphertext[0] ^= 1
    tampered_package["ciphertext"] = bytes(tampered_ciphertext)
    
    try:
        receive_secure_file_dh(
            package=tampered_package,
            receiver_dh_private_key=bob_dh_private,
            sender_public_key=loaded_alice_public,
        )
        print("Unexpected success: tampered package was accepted.")
    except ValueError as e:
        print("Tampering detected successfully:", e)


if __name__ == "__main__":
    main()