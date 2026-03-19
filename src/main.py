from rsa_utils import (
    generate_rsa_key_pair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    encrypt_with_public_key,
    decrypt_with_private_key,
)
from signature_utils import sign_message, verify_signature


def main() -> None:
    private_key, public_key = generate_rsa_key_pair()

    save_private_key(private_key, "keys/alice_private.pem")
    save_public_key(public_key, "keys/alice_public.pem")

    loaded_private_key = load_private_key("keys/alice_private.pem")
    loaded_public_key = load_public_key("keys/alice_public.pem")

    message = b"Hello, this is a secret AES key."

    ciphertext = encrypt_with_public_key(loaded_public_key, message)
    decrypted_message = decrypt_with_private_key(loaded_private_key, ciphertext)

    signature = sign_message(loaded_private_key, message)
    is_signature_valid = verify_signature(loaded_public_key, message, signature)

    print("Original message:", message)
    print("Decrypted message:", decrypted_message)
    print("RSA test successful:", message == decrypted_message)
    print("Signature valid:", is_signature_valid)


if __name__ == "__main__":
    main()
