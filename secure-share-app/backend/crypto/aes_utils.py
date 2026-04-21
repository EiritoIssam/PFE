"""
AES-256-GCM encryption utilities.
GCM mode provides both encryption AND authentication (AEAD).
No need for separate HMAC — the auth tag detects any tampering.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit AES key."""
    return os.urandom(32)  # 256 bits


def encrypt_file(file_bytes: bytes, aes_key: bytes) -> dict:
    """
    Encrypt file bytes using AES-256-GCM.

    Returns a dict with:
        - nonce   : 12-byte random nonce (base64)
        - ciphertext : encrypted file + 16-byte auth tag (base64)
    """
    nonce = os.urandom(12)  # 96-bit nonce — GCM standard
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)  # AAD = None

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_file(ciphertext_b64: str, nonce_b64: str, aes_key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext back to original file bytes.
    Raises InvalidTag if the data was tampered with.
    """
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
