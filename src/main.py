from pathlib import Path

from rsa_utils import (
    generate_rsa_key_pair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)
from file_transfer import secure_file_for_transfer, receive_secure_file


def main() -> None:
    # Ensure folders exist
    Path("input").mkdir(exist_ok=True)
    Path("output").mkdir(exist_ok=True)
    Path("keys").mkdir(exist_ok=True)

    # ==== TEST CASE 1: TEXT FILE ====
    input_file_path = Path("input/sample.txt")
    output_file_path = Path("output/decrypted_sample.txt")

    # ==== TEST CASE 2: JSON FILE ====
    # input_file_path = Path("input/data.json")
    # output_file_path = Path("output/decrypted_data.json")

    # Create a sample input file if it does not exist yet
    if not input_file_path.exists():
        input_file_path.write_text(
            "This is a test file for secure transfer.",
            encoding="utf-8"
        )

    # Alice = sender
    alice_private_key, alice_public_key = generate_rsa_key_pair()
    save_private_key(alice_private_key, "keys/alice_private.pem")
    save_public_key(alice_public_key, "keys/alice_public.pem")

    # Bob = receiver
    bob_private_key, bob_public_key = generate_rsa_key_pair()
    save_private_key(bob_private_key, "keys/bob_private.pem")
    save_public_key(bob_public_key, "keys/bob_public.pem")

    # Load keys back from files
    loaded_alice_private = load_private_key("keys/alice_private.pem")
    loaded_alice_public = load_public_key("keys/alice_public.pem")
    loaded_bob_private = load_private_key("keys/bob_private.pem")
    loaded_bob_public = load_public_key("keys/bob_public.pem")

    # Read real file data from input folder
    file_data = input_file_path.read_bytes()

    print("\n=== Secure File Sharing Demo ===")
    print("Input file:", input_file_path)
    print("Original file data:", file_data)

    # Alice secures the file for Bob
    package = secure_file_for_transfer(
        file_data=file_data,
        sender_private_key=loaded_alice_private,
        receiver_public_key=loaded_bob_public,
    )

    # Bob receives and decrypts the file
    decrypted_file = receive_secure_file(
        package=package,
        receiver_private_key=loaded_bob_private,
        sender_public_key=loaded_alice_public,
    )

    # Save decrypted result to output folder
    output_file_path.write_bytes(decrypted_file)

    print("Output file:", output_file_path)
    print("Decrypted file data:", decrypted_file)
    print("Transfer successful:", file_data == decrypted_file)

    # Tampering test: modify ciphertext after signing
    print("\n=== Tampering Test ===")
    tampered_package = package.copy()
    tampered_ciphertext = bytearray(package["ciphertext"])
    tampered_ciphertext[0] ^= 1  # flip one bit
    tampered_package["ciphertext"] = bytes(tampered_ciphertext)

    try:
        receive_secure_file(
            package=tampered_package,
            receiver_private_key=loaded_bob_private,
            sender_public_key=loaded_alice_public,
        )
        print("Unexpected success: tampered package was accepted.")
    except ValueError as e:
        print("Tampering detected successfully:", e)


if __name__ == "__main__":
    main()