from rsa_utils import (
    generate_rsa_key_pair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)
from file_transfer import secure_file_for_transfer, receive_secure_file


def main() -> None:
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

    file_data = b"This is a confidential file."

    package = secure_file_for_transfer(
        file_data=file_data,
        sender_private_key=loaded_alice_private,
        receiver_public_key=loaded_bob_public,
    )

    decrypted_file = receive_secure_file(
        package=package,
        receiver_private_key=loaded_bob_private,
        sender_public_key=loaded_alice_public,
    )

    print("Original file:", file_data)
    print("Decrypted file:", decrypted_file)
    print("Transfer successful:", file_data == decrypted_file)


if __name__ == "__main__":
    main()
