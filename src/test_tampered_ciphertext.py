from pathlib import Path

from rsa_utils import (
    generate_rsa_key_pair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)
from dh_utils import generate_dh_key_pair, serialize_public_key
from signature_utils import sign_public_key_bytes
from file_transfer import secure_file_for_transfer_dh, receive_secure_file_dh


def main():
    print("\n========== Test: Tampered Ciphertext ==========\n")

    Path("input").mkdir(exist_ok=True)
    Path("keys").mkdir(exist_ok=True)

    input_file_path = Path("input/sample.txt")
    if not input_file_path.exists():
        input_file_path.write_text(
            "This is a test file for secure transfer.",
            encoding="utf-8"
        )

    print("[1] Generating Alice RSA key pair...")
    alice_private_key, alice_public_key = generate_rsa_key_pair()
    save_private_key(alice_private_key, "keys/alice_private.pem")
    save_public_key(alice_public_key, "keys/alice_public.pem")
    print("    Alice RSA keys ready.\n")

    print("[2] Generating Bob RSA key pair...")
    bob_rsa_private_key, bob_rsa_public_key = generate_rsa_key_pair()
    save_private_key(bob_rsa_private_key, "keys/bob_private.pem")
    save_public_key(bob_rsa_public_key, "keys/bob_public.pem")
    print("    Bob RSA keys ready.\n")

    print("[3] Generating Bob DH key pair...")
    bob_dh_private, bob_dh_public, _ = generate_dh_key_pair()
    bob_dh_public_bytes = serialize_public_key(bob_dh_public)
    print("    Bob DH public key generated.\n")

    print("[4] Bob signs his DH public key...")
    bob_dh_public_signature = sign_public_key_bytes(
        bob_rsa_private_key,
        bob_dh_public_bytes
    )
    print("    Signature created.\n")

    print("[5] Loading required keys...")
    loaded_alice_private = load_private_key("keys/alice_private.pem")
    loaded_alice_public = load_public_key("keys/alice_public.pem")
    loaded_bob_rsa_public = load_public_key("keys/bob_public.pem")
    file_data = input_file_path.read_bytes()
    print("    Keys loaded successfully.\n")

    print("[6] Alice creates a normal secure package...")
    package = secure_file_for_transfer_dh(
        file_data=file_data,
        sender_private_key=loaded_alice_private,
        receiver_public_key_bytes=bob_dh_public_bytes,
        receiver_public_key_signature=bob_dh_public_signature,
        receiver_signing_public_key=loaded_bob_rsa_public,
    )
    print("    Secure package created.\n")

    print("[7] Tampering with ciphertext after package was signed...")
    tampered_package = package.copy()
    tampered_ciphertext = bytearray(package["ciphertext"])
    tampered_ciphertext[0] ^= 1
    tampered_package["ciphertext"] = bytes(tampered_ciphertext)
    print("    Ciphertext modified.\n")

    print("[8] Bob tries to verify and decrypt tampered package...")

    try:
        receive_secure_file_dh(
            package=tampered_package,
            receiver_dh_private_key=bob_dh_private,
            sender_public_key=loaded_alice_public,
        )
        print("    Unexpected success: tampered ciphertext was accepted.")
    except ValueError as e:
        print("    Tampered ciphertext detected successfully.")
        print("    Error:", e)

    print("\n========== Ciphertext Tampering Test Completed ==========\n")


if __name__ == "__main__":
    main()