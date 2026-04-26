#!/usr/bin/env python3
"""
BSH Password Authentication — Linux version
Implements secure password-based authentication for Bluetooth Shell (BSH).

Features:
  • PBKDF2-HMAC-SHA256 (100 000 iterations) password hashing
  • Timing-attack-resistant comparison (hmac.compare_digest)
  • HMAC challenge-response — password is NEVER sent in plaintext
  • Per-user configurable auth methods: password only
  • POSIX file permissions (chmod 0o600) to protect the password DB
"""

import os
import json
import hashlib
import hmac
from pathlib import Path
from typing import Optional, List

from bsh_crypto import BSHCrypto


class BSHPasswordAuth:
    """Manages password-based authentication for BSH."""

    def __init__(self, password_file: str = '~/.bsh/passwords'):
        self.password_file = Path(password_file).expanduser()
        self.crypto = BSHCrypto()
        self.users: dict = {}
        self.load_passwords()

    # ═══════════════════════════════════════════
    # Persistence
    # ═══════════════════════════════════════════

    def load_passwords(self) -> None:
        """Load the password database from disk."""
        if not self.password_file.exists():
            return
        try:
            data = json.loads(self.password_file.read_text(encoding='utf-8'))
            self.users = data.get('users', {})
        except Exception as exc:
            print(f"Warning: could not load password file: {exc}")

    def save_passwords(self) -> None:
        """Persist the password database to disk (mode 0600)."""
        self.password_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.password_file.with_suffix('.tmp')
        tmp.write_text(
            json.dumps({'users': self.users}, indent=2),
            encoding='utf-8',
        )
        tmp.replace(self.password_file)
        # POSIX: restrict to owner-only access (like ~/.ssh/id_rsa)
        try:
            os.chmod(self.password_file, 0o600)
        except OSError as exc:
            print(f"Warning: could not set file permissions on {self.password_file}: {exc}")

    # ═══════════════════════════════════════════
    # Hashing
    # ═══════════════════════════════════════════

    def hash_password(
        self,
        password: str,
        salt: Optional[bytes] = None,
    ) -> tuple:
        """
        Hash *password* with PBKDF2-HMAC-SHA256.

        Args:
            password: Plain-text password (str or bytes)
            salt:     Salt bytes (32-byte random salt generated if None)

        Returns:
            (hash_hex, salt_hex)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        if salt is None:
            salt = os.urandom(32)

        key, _ = self.crypto.derive_key_from_password(password, salt)
        return key.hex(), salt.hex()

    # ═══════════════════════════════════════════
    # Direct password verification (server-side simple check)
    # ═══════════════════════════════════════════

    def verify_password(self, username: str, password: str) -> bool:
        """
        Verify *username* + *password* against stored hash.

        Performs a dummy hash even for unknown users to prevent timing attacks.

        Returns:
            bool: True if credentials are valid.
        """
        if username not in self.users:
            # Constant-time dummy work
            self.hash_password("_dummy_password_to_prevent_timing_oracle_")
            return False

        user_data       = self.users[username]
        stored_hash     = user_data['password_hash']
        salt            = bytes.fromhex(user_data['salt'])
        computed_hash, _ = self.hash_password(password, salt)

        # Constant-time compare
        return hmac.compare_digest(computed_hash, stored_hash)

    # ═══════════════════════════════════════════
    # User management
    # ═══════════════════════════════════════════

    def add_user(
        self,
        username: str,
        password: str,
        system_user: Optional[str] = None,
    ) -> None:
        """
        Add or update a BSH user.

        Args:
            username:    BSH username
            password:    Plain-text password
            system_user: OS username (defaults to *username*)
        """
        password_hash, salt = self.hash_password(password)
        self.users[username] = {
            'password_hash': password_hash,
            'salt':          salt,
            'system_user':   system_user or username,
        }
        self.save_passwords()

    def remove_user(self, username: str) -> bool:
        """Remove *username* from the database. Returns True if found."""
        if username in self.users:
            del self.users[username]
            self.save_passwords()
            return True
        return False

    def list_users(self) -> List[str]:
        """Return a list of all BSH usernames."""
        return list(self.users.keys())

    def get_system_user(self, username: str) -> Optional[str]:
        """Return the OS username bound to *username*, or None."""
        return self.users.get(username, {}).get('system_user', username)

    # ═══════════════════════════════════════════
    # Salt accessor
    # ═══════════════════════════════════════════

    def get_salt(self, username: str) -> Optional[bytes]:
        """Return the stored PBKDF2 salt for *username*, or None."""
        entry = self.users.get(username)
        if entry:
            return bytes.fromhex(entry['salt'])
        return None

    # ═══════════════════════════════════════════
    # HMAC challenge-response (avoids sending the password over the wire)
    # ═══════════════════════════════════════════

    def generate_challenge(self) -> bytes:
        """Generate a 32-byte random challenge."""
        return os.urandom(32)

    def create_password_proof(
        self,
        password: str,
        challenge: bytes,
        salt: bytes,
    ) -> str:
        """
        Client-side: prove knowledge of *password* without revealing it.

        1. Derive a key from *password* + *salt* (same PBKDF2 params as storage).
        2. Return HMAC-SHA256(*challenge*, key).

        Args:
            password:  Plain-text password
            challenge: Server-issued random challenge
            salt:      Salt received from the server for this user

        Returns:
            HMAC hex digest string
        """
        if isinstance(password, str):
            password = password.encode('utf-8')

        key, _ = self.crypto.derive_key_from_password(password, salt)
        return hmac.new(key, challenge, hashlib.sha256).hexdigest()

    def verify_password_proof(
        self,
        username: str,
        challenge: bytes,
        proof: str,
    ) -> bool:
        """
        Server-side: verify the HMAC proof from the client.

        The stored PBKDF2-derived key is used directly as the HMAC key,
        so the server never needs to know the plain-text password.

        Args:
            username:  BSH username
            challenge: Challenge that was sent to the client
            proof:     HMAC hex digest received from the client

        Returns:
            bool: True if the proof is valid.
        """
        if username not in self.users:
            return False

        user_data  = self.users[username]
        stored_key = bytes.fromhex(user_data['password_hash'])   # derived key
        expected   = hmac.new(stored_key, challenge, hashlib.sha256).hexdigest()
        return hmac.compare_digest(proof, expected)


# ─────────────────────────────────────────────────────────────────────────────
# CLI — user-management utility  (bsh-passwd)
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        prog='bsh-passwd',
        description='BSH Password Manager',
    )
    sub = parser.add_subparsers(dest='command')
    sub.required = True

    _pf = dict(
        flags=('-f', '--password-file'),
        kwargs=dict(default='/var/lib/bsh/passwords', metavar='FILE',
                    help='Password database (default: /var/lib/bsh/passwords)'),
    )

    # adduser
    ap = sub.add_parser('adduser', help='Add a BSH user')
    ap.add_argument('username')
    ap.add_argument('-s', '--system-user', help='OS username (if different from BSH username)')
    ap.add_argument(*_pf['flags'], **_pf['kwargs'])

    # deluser
    dp = sub.add_parser('deluser', help='Remove a BSH user')
    dp.add_argument('username')
    dp.add_argument(*_pf['flags'], **_pf['kwargs'])

    # list
    lp = sub.add_parser('list', help='List all BSH users')
    lp.add_argument(*_pf['flags'], **_pf['kwargs'])

    # passwd
    pp = sub.add_parser('passwd', help='Change a user password')
    pp.add_argument('username')
    pp.add_argument(*_pf['flags'], **_pf['kwargs'])

    args = parser.parse_args()
    auth = BSHPasswordAuth(args.password_file)

    # ── adduser ───────────────────────────────────────────────────────────────
    if args.command == 'adduser':
        system_user = args.system_user or args.username
        # Verify the system user actually exists on this Linux system
        try:
            import pwd
            pwd.getpwnam(system_user)
        except KeyError:
            print(f"Warning: system user '{system_user}' not found on this system.")
            if input("Continue anyway? [y/N]: ").lower() != 'y':
                return 1

        password = getpass.getpass(f"Password for {args.username}: ")
        confirm  = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return 1
        if len(password) < 8:
            print("Password must be at least 8 characters.")
            return 1

        auth.add_user(args.username, password, system_user)
        print(f"✓ User '{args.username}' added (OS user: {system_user})")

    # ── deluser ───────────────────────────────────────────────────────────────
    elif args.command == 'deluser':
        if auth.remove_user(args.username):
            print(f"✓ User '{args.username}' removed.")
        else:
            print(f"User '{args.username}' not found.")
            return 1

    # ── list ──────────────────────────────────────────────────────────────────
    elif args.command == 'list':
        users = auth.list_users()
        if not users:
            print("No BSH users configured.")
            return 0
        print(f"\nBSH Users ({len(users)})")
        print("─" * 60)
        for u in users:
            sys_u = auth.get_system_user(u)
            print(f"  {u:<20}  OS: {sys_u}")
        print()

    # ── passwd ────────────────────────────────────────────────────────────────
    elif args.command == 'passwd':
        if args.username not in auth.users:
            print(f"User '{args.username}' not found.")
            return 1

        password = getpass.getpass(f"New password for {args.username}: ")
        confirm  = getpass.getpass("Confirm: ")
        if password != confirm:
            print("Passwords do not match.")
            return 1
        if len(password) < 8:
            print("Password must be at least 8 characters.")
            return 1

        auth.add_user(args.username, password, auth.get_system_user(args.username))
        print(f"✓ Password changed for '{args.username}'.")

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
