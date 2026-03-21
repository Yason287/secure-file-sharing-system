from file_crypto import generate_aes_key, encrypt_file_bytes, decrypt_file_bytes

data = b"Hello secure file sharing"

key = generate_aes_key()
nonce, ciphertext = encrypt_file_bytes(data, key)
decrypted = decrypt_file_bytes(nonce, ciphertext, key)

print("Original:", data)
print("Decrypted:", decrypted)

assert decrypted == data
print("AES works correctly!")

tampered = bytearray(ciphertext)
tampered[0] ^= 1

try:
    decrypt_file_bytes(nonce, bytes(tampered), key)
    print("Unexpected success")
except Exception:
    print("Tampering detected!")