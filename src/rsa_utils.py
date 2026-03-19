from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_rsa_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key: rsa.RSAPrivateKey, file_path: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    path.write_bytes(pem_data)


def save_public_key(public_key: rsa.RSAPublicKey, file_path: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    path.write_bytes(pem_data)


def load_private_key(file_path: str) -> rsa.RSAPrivateKey:
    pem_data = Path(file_path).read_bytes()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )
    return private_key


def load_public_key(file_path: str) -> rsa.RSAPublicKey:
    pem_data = Path(file_path).read_bytes()

    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def encrypt_with_public_key(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_with_private_key(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext