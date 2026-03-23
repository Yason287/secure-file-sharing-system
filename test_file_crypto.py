from file_crypto import generate_aes_key, encrypt_file_bytes, decrypt_file_bytes

# Sample plaintext to simulate file content
data = b"Hello secure file sharing"

# Generate AES key and encrypt the data
key = generate_aes_key()
nonce, ciphertext = encrypt_file_bytes(data, key)

# Decrypt and verify correctness
decrypted = decrypt_file_bytes(nonce, ciphertext, key)

print("Original:", data)
print("Decrypted:", decrypted)

assert decrypted == data
print("AES works correctly!")

# Tampering test: modify one byte of ciphertext
tampered = bytearray(ciphertext)
tampered[0] ^= 1

try:
    decrypt_file_bytes(nonce, bytes(tampered), key)
    print("Unexpected success")
except Exception:
    print("Tampering detected!")