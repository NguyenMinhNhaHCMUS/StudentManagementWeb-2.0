"""
Lab 04 — Client-side cryptographic operations.
All encryption/decryption happens here (Python/Flask acting as "client").
The database only stores and retrieves encrypted data.

RSA key pairs are derived deterministically from the user's password + MANV.
"""

import hashlib

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


# ============================================================
# Hashing
# ============================================================

def sha256_hash(password: str, salt: str) -> bytes:
    """
    Hash password using SHA2_256 with salt.
    Equivalent to SQL Server: HASHBYTES('SHA2_256', @MK + @MANV)
    """
    return hashlib.sha256((password + salt).encode('utf-8')).digest()


# ============================================================
# Deterministic RSA Key Derivation from Password
# ============================================================

def _deterministic_randfunc(seed: bytes):
    """
    Build a deterministic PRNG function from seed using SHA-256 counter mode.
    Each call returns n bytes derived from HMAC-SHA256(seed || counter).
    """
    state = {'counter': 0, 'buffer': b''}

    def randfunc(n: int) -> bytes:
        while len(state['buffer']) < n:
            block = hashlib.sha256(
                seed + state['counter'].to_bytes(4, 'big')
            ).digest()
            state['buffer'] += block
            state['counter'] += 1
        result = state['buffer'][:n]
        state['buffer'] = state['buffer'][n:]
        return result

    return randfunc


def derive_rsa_from_password(password: str, manv: str) -> RSA.RsaKey:
    """
    Deterministically derive an RSA-2048 key pair from password + manv.
    Same password + manv → same key pair every time.

    Steps:
      1. scrypt(password, salt=manv) → 64-byte seed
      2. SHA-256 counter-mode PRNG seeded from above → RSA-2048
    """
    # Step 1: KDF — scrypt stretches the password into a strong seed
    kdf = Scrypt(
        salt=manv.encode('utf-8'),
        length=64,
        n=2 ** 14,   # CPU/memory cost (≈0.1s on modern hardware)
        r=8,
        p=1,
    )
    seed = kdf.derive(password.encode('utf-8'))

    # Step 2: Build deterministic PRNG, then generate RSA-2048
    rng = _deterministic_randfunc(seed)
    private_key = RSA.generate(2048, randfunc=rng)
    return private_key


# ============================================================
# Public Key Serialization (for DB storage)
# ============================================================

def serialize_public_key(private_key: RSA.RsaKey) -> str:
    """Export public key to PEM string for storage in DB (PUBKEY column)."""
    return private_key.publickey().export_key('PEM').decode('utf-8')


def load_public_key_from_pem(pem_str: str) -> RSA.RsaKey:
    """Import a public key from PEM string stored in DB."""
    return RSA.import_key(pem_str.encode('utf-8'))


# ============================================================
# RSA Encryption / Decryption  (OAEP + SHA-256)
# ============================================================

def rsa_encrypt(public_key: RSA.RsaKey, plaintext: str) -> bytes:
    """
    Encrypt plaintext string using RSA public key with OAEP+SHA-256 padding.
    Returns ciphertext as bytes (suitable for VARBINARY storage).
    """
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(plaintext.encode('utf-8'))


def rsa_decrypt(private_key: RSA.RsaKey, ciphertext: bytes) -> str:
    """
    Decrypt ciphertext bytes using RSA private key with OAEP+SHA-256 padding.
    Returns plaintext string.
    """
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext).decode('utf-8')
