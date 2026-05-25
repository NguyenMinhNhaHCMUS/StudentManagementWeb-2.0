"""
Lab 04 — Client-side cryptographic operations.
All encryption/decryption happens here (Python/Flask acting as "client").
The database only stores and retrieves encrypted data.
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Directory for storing encrypted private key files
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')


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
# RSA Key Generation & Serialization
# ============================================================

def generate_rsa_keypair():
    """Generate an RSA 2048 key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> str:
    """Serialize public key to PEM-encoded string for DB storage."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode('utf-8')


def load_public_key_from_pem(pem_str: str):
    """Load a public key object from a PEM-encoded string."""
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))


# ============================================================
# Private Key File Storage
# ============================================================

def save_private_key_file(manv: str, private_key, password: str):
    """
    Save private key to keys/{manv}.pem, encrypted with the user's password.
    The password protects the private key at rest via AES encryption.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode('utf-8')
        ),
    )
    filepath = os.path.join(KEYS_DIR, f'{manv}.pem')
    with open(filepath, 'wb') as f:
        f.write(pem)


def load_private_key_file(manv: str, password: str):
    """
    Load and decrypt private key from keys/{manv}.pem.
    Raises ValueError if password is wrong.
    Raises FileNotFoundError if key file is missing.
    """
    filepath = os.path.join(KEYS_DIR, f'{manv}.pem')
    with open(filepath, 'rb') as f:
        pem = f.read()
    return serialization.load_pem_private_key(
        pem, password=password.encode('utf-8')
    )


# ============================================================
# RSA Encryption / Decryption
# ============================================================

def rsa_encrypt(public_key, plaintext: str) -> bytes:
    """
    Encrypt plaintext string using RSA public key with OAEP padding.
    Returns ciphertext as bytes (suitable for VARBINARY storage).
    """
    return public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> str:
    """
    Decrypt ciphertext bytes using RSA private key with OAEP padding.
    Returns plaintext string.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode('utf-8')
