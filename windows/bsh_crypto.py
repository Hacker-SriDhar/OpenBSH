#!/usr/bin/env python3
"""
BSH Cryptographic utilities
Provides symmetric session encryption and password hashing utilities.
"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BSHCrypto:
    """Handles symmetric cryptographic operations for BSH."""

    def __init__(self):
        self.backend = default_backend()

    # ═══════════════════════════════════════════════════════════
    # Utilities
    # ═══════════════════════════════════════════════════════════

    def generate_challenge(self, size=32) -> bytes:
        return os.urandom(size)

    # ═══════════════════════════════════════════════════════════
    # Session encryption (AES-256-GCM)
    # ═══════════════════════════════════════════════════════════

    def generate_session_key(self) -> bytes:
        return os.urandom(32)

    def derive_key_from_password(self, password, salt=None):
        """PBKDF2-HMAC-SHA256 key derivation. Returns (key, salt)."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100_000, backend=self.backend,
        )
        return kdf.derive(password), salt

    def encrypt_data(self, key: bytes, plaintext: bytes) -> bytes:
        """AES-256-GCM encrypt. Returns IV(12) + ciphertext + tag(16)."""
        iv  = os.urandom(12)
        enc = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend).encryptor()
        ct  = enc.update(plaintext) + enc.finalize()
        return iv + ct + enc.tag

    def decrypt_data(self, key: bytes, encrypted: bytes) -> bytes:
        """AES-256-GCM decrypt. Input format: IV(12) + ciphertext + tag(16)."""
        iv, tag, ct = encrypted[:12], encrypted[-16:], encrypted[12:-16]
        dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend).decryptor()
        return dec.update(ct) + dec.finalize()