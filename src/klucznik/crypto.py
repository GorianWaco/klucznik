from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC = b"KLUCZNIK1"
NONCE_LEN = 12


def derive_vault_key(hmac_secret: bytes, username: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"klucznik-vault-v1",
        info=username.encode("utf-8"),
    ).derive(hmac_secret)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    return MAGIC + nonce + ct


def decrypt(key: bytes, blob: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("To nie jest sejf Klucznika.")
    nonce = blob[len(MAGIC) : len(MAGIC) + NONCE_LEN]
    ct = blob[len(MAGIC) + NONCE_LEN :]
    return AESGCM(key).decrypt(nonce, ct, MAGIC)
