"""
RSA-2048 + OAEP utilities for AES key wrapping.

Flow:
  - User registration  → generate RSA keypair, store public key in DB,
                         return private key to client (never stored server-side).
  - File upload        → encrypt AES key with recipient's RSA public key.
  - File download      → decrypt AES key with recipient's RSA private key.
"""

import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generate an RSA-2048 keypair.

    Returns:
        (private_key_pem, public_key_pem)  — both as PEM strings.
    The private key is returned to the client and NEVER stored on the server.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_pem, public_pem


# ---------------------------------------------------------------------------
# Key wrapping / unwrapping
# ---------------------------------------------------------------------------

def encrypt_aes_key(aes_key: bytes, public_key_pem: str) -> str:
    """
    Wrap (encrypt) an AES key with a recipient's RSA public key using OAEP.

    Returns base64-encoded ciphertext.
    """
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend(),
    )
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode()


def decrypt_aes_key(encrypted_aes_key_b64: str, private_key_pem: str) -> bytes:
    """
    Unwrap (decrypt) an AES key using the recipient's RSA private key.

    Returns the original AES key bytes.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend(),
    )
    encrypted = base64.b64decode(encrypted_aes_key_b64)
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
