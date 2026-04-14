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
    print("\n========== Secure File Sharing Demo ==========\n")

    print("[1] Creating required folders...")
    Path("input").mkdir(exist_ok=True)
    Path("output").mkdir(exist_ok=True)
    Path("keys").mkdir(exist_ok=True)
    print("    Folders ready.\n")

    print("[2] Checking sample input files...")
    txt_input_path = Path("input/sample.txt")
    if not txt_input_path.exists():
        txt_input_path.write_text(
            "This is a test file for secure transfer.",
            encoding="utf-8"
        )
        print("    Created input/sample.txt")

    json_input_path = Path("input/data.json")
    if not json_input_path.exists():
        json_input_path.write_text(
            '{\n'
            '  "user": "Alice",\n'
            '  "role": "sender",\n'
            '  "message": "This is a secure JSON file"\n'
            '}',
            encoding="utf-8"
        )
        print("    Created input/data.json")

    input_file_path = Path("input/sample.txt")
    output_file_path = Path("output/decrypted_sample.txt")
    print(f"    Using input file: {input_file_path}\n")

    print("[3] Generating Alice RSA key pair for signing...")
    alice_private_key, alice_public_key = generate_rsa_key_pair()
    save_private_key(alice_private_key, "keys/alice_private.pem")
    save_public_key(alice_public_key, "keys/alice_public.pem")
    print("    Alice RSA keys generated and saved.\n")

    print("[4] Generating Bob RSA key pair for authenticating his DH public key...")
    bob_rsa_private_key, bob_rsa_public_key = generate_rsa_key_pair()
    save_private_key(bob_rsa_private_key, "keys/bob_private.pem")
    save_public_key(bob_rsa_public_key, "keys/bob_public.pem")
    print("    Bob RSA keys generated and saved.\n")

    print("[5] Generating Bob DH key pair for key exchange...")
    bob_dh_private, bob_dh_public, _ = generate_dh_key_pair()
    bob_dh_public_bytes = serialize_public_key(bob_dh_public)
    Path("keys/bob_dh_public.pem").write_bytes(bob_dh_public_bytes)
    print("    Bob DH key pair generated.")
    print("    Bob DH public key serialized and saved.\n")

    print("[6] Bob signs his DH public key using his RSA private key...")
    bob_dh_public_signature = sign_public_key_bytes(
        bob_rsa_private_key,
        bob_dh_public_bytes
    )
    print("    Bob DH public key signed successfully.\n")

    print("[7] Loading Alice and Bob public/private keys from disk...")
    loaded_alice_private = load_private_key("keys/alice_private.pem")
    loaded_alice_public = load_public_key("keys/alice_public.pem")
    loaded_bob_rsa_public = load_public_key("keys/bob_public.pem")
    print("    Keys loaded successfully.\n")

    print("[8] Reading input file contents...")
    file_data = input_file_path.read_bytes()
    print(f"    Read {len(file_data)} bytes from input file.\n")

    print("[9] Alice prepares secure package for Bob...")
    print("    - Verifying Bob's DH public key signature")
    print("    - Generating Alice ephemeral DH key pair")
    print("    - Deriving shared AES key using DH + HKDF")
    print("    - Encrypting file with AES-GCM")
    print("    - Signing transfer package with Alice's RSA private key")

    package = secure_file_for_transfer_dh(
        file_data=file_data,
        sender_private_key=loaded_alice_private,
        receiver_public_key_bytes=bob_dh_public_bytes,
        receiver_public_key_signature=bob_dh_public_signature,
        receiver_signing_public_key=loaded_bob_rsa_public,
    )
    print("    Secure package created successfully.\n")

    print("[10] Bob receives secure package...")
    print("     - Verifying Alice's package signature")
    print("     - Recovering Alice's DH public key")
    print("     - Deriving shared AES key using Bob's DH private key")
    print("     - Decrypting file with AES-GCM")

    decrypted_file = receive_secure_file_dh(
        package=package,
        receiver_dh_private_key=bob_dh_private,
        sender_public_key=loaded_alice_public,
    )
    print("     Package verified and file decrypted successfully.\n")

    print("[11] Saving decrypted output file...")
    output_file_path.write_bytes(decrypted_file)
    print(f"     Output saved to: {output_file_path}\n")

    print("[12] Final validation...")
    print("     Original file content :", file_data)
    print("     Decrypted file content:", decrypted_file)
    print("     Transfer successful   :", file_data == decrypted_file)

    print("\n========== Demo Completed ==========\n")


if __name__ == "__main__":
    main()