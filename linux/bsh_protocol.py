#!/usr/bin/env python3
"""
BSH Protocol — Bluetooth Shell packet format and authentication flow.

Packet wire format
──────────────────
  ┌──────┬────────┬──────┬─────────┬──────────┐
  │ SOF  │ Length │ Type │ Payload │ Checksum │
  │ 1 B  │  2 B   │  1 B │  N B    │   1 B    │
  └──────┴────────┴──────┴─────────┴──────────┘
  SOF      = 0xAA
  Length   = len(Payload), big-endian uint16
  Checksum = XOR of all header bytes + all payload bytes

Authentication flows
────────────────────
  Password (client initiates):
    Client → MSG_AUTH_PASSWORD_REQUEST   {}
    Server → MSG_AUTH_PASSWORD_CHALLENGE {challenge_hex}
    Client → MSG_AUTH_PASSWORD_RESPONSE  {password (plaintext inside BT link)}
    Server → MSG_AUTH_SUCCESS            {status, username, session_key_hex}
          OR MSG_AUTH_FAILURE            {error}
"""

import struct
import json
from enum import IntEnum
from typing import Optional, Tuple

from bsh_crypto import BSHCrypto


# ─────────────────────────────────────────────────────────────────────────────
# Message-Type Dictionary
# ─────────────────────────────────────────────────────────────────────────────

class MessageType(IntEnum):
    # ── Handshake / control ─────────────────────────────────
    MSG_HELLO      = 0x01
    MSG_DISCONNECT = 0x02
    MSG_KEEPALIVE  = 0x03

    # ── Authentication outcomes ─────────────────────────────
    MSG_AUTH_SUCCESS   = 0x07   # Server → Client: session key
    MSG_AUTH_FAILURE   = 0x08   # Server → Client: error message

    # ── Password authentication ──────────────────────────────
    MSG_AUTH_PASSWORD_REQUEST   = 0x09  # Client → Server: "I want password auth"
    MSG_AUTH_PASSWORD_CHALLENGE = 0x0A  # Server → Client: random challenge
    MSG_AUTH_PASSWORD_RESPONSE  = 0x0B  # Client → Server: password (or HMAC proof)

    # ── Data streams ─────────────────────────────────────────
    MSG_DATA_IN  = 0x10   # Client → Server  (stdin)
    MSG_DATA_OUT = 0x11   # Server → Client  (stdout)
    MSG_DATA_ERR = 0x12   # Server → Client  (stderr)

    # ── Terminal control ─────────────────────────────────────
    MSG_INTERRUPT     = 0x20
    MSG_WINDOW_SIZE   = 0x21
    MSG_WINDOW_RESIZE = 0x15


# ─────────────────────────────────────────────────────────────────────────────
# Packet
# ─────────────────────────────────────────────────────────────────────────────

class BSHPacket:
    """A single BSH protocol packet."""

    SOF = 0xAA      # Start-of-Frame magic byte

    def __init__(self, msg_type: MessageType, payload: bytes = b''):
        self.msg_type = msg_type
        self.payload  = payload

    # ── Checksum ──────────────────────────────────────────────────────────────

    def _checksum(self, length: int) -> int:
        """XOR checksum over Length (2 B) + Type (1 B) + all payload bytes.
        Note: the SOF byte (0xAA) is intentionally excluded from the checksum."""
        cs = (length >> 8) & 0xFF
        cs ^= length & 0xFF
        cs ^= int(self.msg_type)
        for b in self.payload:
            cs ^= b
        return cs & 0xFF

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        """Serialise packet to wire bytes."""
        length   = len(self.payload)
        checksum = self._checksum(length)
        header   = struct.pack('!BHB', self.SOF, length, int(self.msg_type))
        return header + self.payload + struct.pack('!B', checksum)

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['BSHPacket']:
        """
        Parse a packet from raw bytes.

        Returns:
            BSHPacket if valid, None otherwise.
        """
        if len(data) < 5:
            return None

        if data[0] != cls.SOF:
            return None

        length   = struct.unpack('!H', data[1:3])[0]
        msg_type = data[3]

        expected_size = 4 + length + 1
        if len(data) < expected_size:
            return None

        payload           = data[4:4 + length]
        received_checksum = data[4 + length]

        try:
            mt = MessageType(msg_type)
        except ValueError:
            return None

        pkt = cls(mt, payload)
        if pkt._checksum(length) != received_checksum:
            return None

        return pkt

    def __repr__(self) -> str:
        return (
            f"BSHPacket(type={MessageType(self.msg_type).name}, "
            f"len={len(self.payload)})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Authenticator
# ─────────────────────────────────────────────────────────────────────────────

class BSHAuthenticator:
    """
    Stateful authentication helper for a single BSH connection.

    Both host-side and client-side methods are provided.
    """

    def __init__(self, crypto: BSHCrypto):
        self.crypto           = crypto
        self.authenticated    = False
        self.client_id        = None
        self.session_key: Optional[bytes] = None
        self._pending_challenge: Optional[bytes] = None

    # ═══════════════════════════════════════════
    # ── Host side — Password auth ────────────────
    # ═══════════════════════════════════════════

    def handle_password_auth_request(self, packet: 'BSHPacket') -> 'BSHPacket':
        """
        Host: client wants password auth → issue a random challenge.

        Returns:
            MSG_AUTH_PASSWORD_CHALLENGE
        """
        self._pending_challenge = self.crypto.generate_challenge(32)
        return BSHPacket(
            MessageType.MSG_AUTH_PASSWORD_CHALLENGE,
            _json({'challenge': self._pending_challenge.hex()}),
        )

    def handle_password_auth_response(
        self,
        packet: 'BSHPacket',
        username: str,
        password_auth,           # BSHPasswordAuth instance
    ) -> 'BSHPacket':
        """
        Host: verify the password response → success or failure.

        Two verification paths:
          • If payload has ``'proof'``: HMAC challenge-response (preferred).
          • If payload has ``'password'``: direct password check (simpler clients).

        Returns:
            MSG_AUTH_SUCCESS or MSG_AUTH_FAILURE
        """
        try:
            data  = json.loads(packet.payload.decode('utf-8'))
            proof = data.get('proof')

            if proof is not None:
                # HMAC proof path
                valid = password_auth.verify_password_proof(
                    username, self._pending_challenge, proof
                )
            else:
                # Plaintext-password path (simple / legacy clients)
                pw    = data.get('password', '')
                valid = password_auth.verify_password(username, pw)

            self._pending_challenge = None

            if valid:
                self.session_key   = self.crypto.generate_session_key()
                self.authenticated = True
                return BSHPacket(
                    MessageType.MSG_AUTH_SUCCESS,
                    _json({'status': 'authenticated', 'username': username,
                           'session_key': self.session_key.hex()}),
                )
            return _failure('Authentication failed')

        except Exception as exc:
            return _failure(str(exc))

    # ═══════════════════════════════════════════
    # ── Client side — Password auth ──────────────
    # ═══════════════════════════════════════════

    def create_password_auth_request(self) -> 'BSHPacket':
        """Client: initiate password authentication."""
        return BSHPacket(MessageType.MSG_AUTH_PASSWORD_REQUEST, _json({}))

    def create_password_response(
        self,
        packet: 'BSHPacket',
        password: str,
        salt: Optional[bytes] = None,
    ) -> 'BSHPacket':
        """
        Client: respond to MSG_AUTH_PASSWORD_CHALLENGE.

        If *salt* is provided, uses HMAC challenge-response.
        Otherwise falls back to sending the plaintext password.

        Args:
            packet:   MSG_AUTH_PASSWORD_CHALLENGE from server
            password: User's plain-text password
            salt:     PBKDF2 salt for this user (received out-of-band or from server)

        Returns:
            MSG_AUTH_PASSWORD_RESPONSE
        """
        data      = json.loads(packet.payload.decode('utf-8'))
        challenge = bytes.fromhex(data['challenge'])

        if salt is not None:
            import hashlib, hmac as _hmac
            key, _ = self.crypto.derive_key_from_password(password, salt)
            if isinstance(password, str):
                password = password.encode('utf-8')
            proof = _hmac.new(key, challenge, hashlib.sha256).hexdigest()
            return BSHPacket(
                MessageType.MSG_AUTH_PASSWORD_RESPONSE,
                _json({'proof': proof}),
            )
        else:
            # Plaintext fallback (acceptable on encrypted BT link)
            return BSHPacket(
                MessageType.MSG_AUTH_PASSWORD_RESPONSE,
                _json({'password': password}),
            )

    def handle_auth_success(self, packet: 'BSHPacket') -> bool:
        """
        Client: process MSG_AUTH_SUCCESS and extract/store the session key.

        Returns:
            bool: True if extraction succeeded.
        """
        try:
            data             = json.loads(packet.payload.decode('utf-8'))
            self.session_key = bytes.fromhex(data['session_key'])
            self.authenticated = True
            return True
        except Exception as exc:
            print(f"BSHAuthenticator: failed to extract session key: {exc}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _json(data: dict) -> bytes:
    return json.dumps(data).encode('utf-8')


def _failure(msg: str) -> BSHPacket:
    return BSHPacket(MessageType.MSG_AUTH_FAILURE, _json({'error': msg}))


def create_hello_packet(capabilities: dict) -> BSHPacket:
    """Build a MSG_HELLO packet."""
    return BSHPacket(MessageType.MSG_HELLO, _json(capabilities))


def create_data_packet(
    text: str,
    msg_type: MessageType = MessageType.MSG_DATA_IN,
) -> BSHPacket:
    """Build a data (stdin/stdout/stderr) packet."""
    return BSHPacket(msg_type, text.encode('utf-8'))


def create_window_size_packet(rows: int, cols: int) -> BSHPacket:
    """Build a MSG_WINDOW_SIZE packet."""
    return BSHPacket(MessageType.MSG_WINDOW_SIZE, struct.pack('!HH', rows, cols))


def parse_window_size(packet: BSHPacket) -> Tuple[int, int]:
    """Unpack rows, cols from a MSG_WINDOW_SIZE packet."""
    return struct.unpack('!HH', packet.payload)


# ─────────────────────────────────────────────────────────────────────────────
# Quick smoke-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("BSH Protocol — packet smoke-test\n")

    hello = create_hello_packet({'name': 'BSH-Host', 'version': '1.0', 'os': 'Linux'})
    print(f"Created  : {hello}")
    print(f"Wire hex : {hello.to_bytes().hex()}")

    parsed = BSHPacket.from_bytes(hello.to_bytes())
    assert parsed is not None, "Parse failed!"
    print(f"Parsed   : {parsed}")
    print(f"Payload  : {json.loads(parsed.payload)}")
    print()

    data = create_data_packet("ls -la\n")
    print(f"Data pkt : {data}")

    ws = create_window_size_packet(24, 80)
    rows, cols = parse_window_size(ws)
    print(f"Win size : {rows}×{cols}")

    print("\nAll packet tests passed ✓")
