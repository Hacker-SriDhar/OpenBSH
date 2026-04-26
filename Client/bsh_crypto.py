#!/usr/bin/env python3
"""
BSH Cryptographic utilities — Client version.

Provides the same AES-256-GCM session encryption and PBKDF2 key derivation
used by both the Windows and Linux BSH servers to ensure full compatibility.

NOTE: This file must stay in sync with:
  - linux/bsh_crypto.py      (Linux server)
  - bsh_crypto.py            (Windows server)

The client only uses:  generate_session_key, encrypt_data, decrypt_data,
                       derive_key_from_password, generate_challenge
All other server-only functionality (keypair generation, authorized_keys DB)
is intentionally omitted here.
"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BSHCrypto:
    """Handles symmetric cryptographic operations for BSH clients."""

    def __init__(self):
        self.backend = default_backend()

    # ═══════════════════════════════════════════════════════════
    # Utilities
    # ═══════════════════════════════════════════════════════════

    def generate_challenge(self, size: int = 32) -> bytes:
        """Generate a cryptographically random challenge byte string."""
        return os.urandom(size)

    # ═══════════════════════════════════════════════════════════
    # Session encryption — AES-256-GCM
    #
    # Wire format:  IV(12 B) | ciphertext(N B) | GCM tag(16 B)
    #
    # This layout is IDENTICAL to the server implementation.
    # Any change here must be mirrored in linux/bsh_crypto.py
    # and bsh_crypto.py (Windows server).
    # ═══════════════════════════════════════════════════════════

    def generate_session_key(self) -> bytes:
        """Return a 256-bit (32-byte) random session key."""
        return os.urandom(32)

    def derive_key_from_password(self, password, salt=None):
        """
        PBKDF2-HMAC-SHA256 key derivation.

        Args:
            password: str or bytes
            salt:     16-byte salt (generated randomly if None)

        Returns:
            (key: bytes, salt: bytes)  — 32-byte key, 16-byte salt
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=self.backend,
        )
        return kdf.derive(password), salt

    def encrypt_data(self, key: bytes, plaintext: bytes) -> bytes:
        """
        AES-256-GCM encrypt.

        Args:
            key:       32-byte session key
            plaintext: bytes to encrypt (may be empty b'' for keepalives)

        Returns:
            IV(12 B) + ciphertext(N B) + GCM-tag(16 B)
        """
        iv  = os.urandom(12)
        enc = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend,
        ).encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        return iv + ct + enc.tag

    def decrypt_data(self, key: bytes, encrypted: bytes) -> bytes:
        """
        AES-256-GCM decrypt.

        Args:
            key:       32-byte session key
            encrypted: IV(12 B) + ciphertext + GCM-tag(16 B)

        Returns:
            Decrypted plaintext bytes.

        Raises:
            cryptography.exceptions.InvalidTag: if authentication fails.
        """
        if len(encrypted) < 28:
            raise ValueError(
                f"Encrypted payload too short: {len(encrypted)} bytes "
                f"(minimum 28: 12 IV + 0 data + 16 tag)"
            )
        iv  = encrypted[:12]
        tag = encrypted[-16:]
        ct  = encrypted[12:-16]
        dec = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend,
        ).decryptor()
        return dec.update(ct) + dec.finalize()
