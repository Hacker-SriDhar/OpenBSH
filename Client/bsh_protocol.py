#!/usr/bin/env python3
"""
BSH Protocol — Bluetooth Shell packet format and authentication flow.

This file is IDENTICAL to the server-side bsh_protocol.py files in both
the Windows server root and linux/ directory.  Keep all three in sync.

Packet wire format
──────────────────
  ┌──────┬────────┬──────┬─────────┬──────────┐
  │ SOF  │ Length │ Type │ Payload │ Checksum │
  │ 1 B  │  2 B   │  1 B │  N B    │   1 B    │
  └──────┴────────┴──────┴─────────┴──────────┘
  SOF      = 0xAA
  Length   = len(Payload), big-endian uint16
  Checksum = XOR of Length(2B) + Type(1B) + Payload bytes
             (SOF byte intentionally excluded)

Authentication flow (password)
────────────────────────────────
  Client → MSG_AUTH_PASSWORD_REQUEST   {}
  Server → MSG_AUTH_PASSWORD_CHALLENGE {challenge: <32-byte hex>}
  Client → MSG_AUTH_PASSWORD_RESPONSE  {password: <plaintext>}
  Server → MSG_AUTH_SUCCESS            {status, username, session_key: <hex>}
        OR MSG_AUTH_FAILURE            {error}

  All packets AFTER MSG_AUTH_SUCCESS are AES-256-GCM encrypted.
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
    MSG_AUTH_PASSWORD_REQUEST   = 0x09  # Client → Server
    MSG_AUTH_PASSWORD_CHALLENGE = 0x0A  # Server → Client
    MSG_AUTH_PASSWORD_RESPONSE  = 0x0B  # Client → Server

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
        The SOF byte (0xAA) is intentionally excluded from the checksum."""
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
            BSHPacket if valid, None if data is too short, SOF wrong, or
            checksum mismatch.
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
            return None     # unknown message type — discard

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
# BSHAuthenticator  (client-side helper — not used by the password-only flow
#                    but kept for API compatibility)
# ─────────────────────────────────────────────────────────────────────────────

class BSHAuthenticator:
    """Stateful authentication helper."""

    def __init__(self, crypto: BSHCrypto):
        self.crypto            = crypto
        self.authenticated     = False
        self.client_id         = None
        self.session_key: Optional[bytes] = None
        self._pending_challenge: Optional[bytes] = None

    def handle_auth_success(self, packet: 'BSHPacket') -> bool:
        """Client: extract session key from MSG_AUTH_SUCCESS."""
        try:
            data             = json.loads(packet.payload.decode('utf-8'))
            self.session_key = bytes.fromhex(data['session_key'])
            self.authenticated = True
            return True
        except Exception as exc:
            print(f"BSHAuthenticator: failed to extract session key: {exc}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions — used directly by both client files
# ─────────────────────────────────────────────────────────────────────────────

def create_hello_packet(capabilities: dict) -> BSHPacket:
    """Build a MSG_HELLO packet."""
    return BSHPacket(MessageType.MSG_HELLO, json.dumps(capabilities).encode('utf-8'))


def create_data_packet(
    text: str,
    msg_type: MessageType = MessageType.MSG_DATA_IN,
) -> BSHPacket:
    """Build a data (stdin/stdout/stderr) packet from a text string."""
    return BSHPacket(msg_type, text.encode('utf-8'))


def create_window_size_packet(rows: int, cols: int) -> BSHPacket:
    """Build a MSG_WINDOW_SIZE packet."""
    return BSHPacket(MessageType.MSG_WINDOW_SIZE, struct.pack('!HH', rows, cols))


def parse_window_size(packet: BSHPacket) -> Tuple[int, int]:
    """Unpack (rows, cols) from a MSG_WINDOW_SIZE packet."""
    return struct.unpack('!HH', packet.payload)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    print("BSH Protocol — client-copy smoke-test\n")

    # Round-trip test
    hello = create_hello_packet({'name': 'BSH-Client', 'version': '1.0'})
    print(f"Created  : {hello}")
    wire   = hello.to_bytes()
    parsed = BSHPacket.from_bytes(wire)
    assert parsed is not None, "Parse failed!"
    assert parsed.msg_type == MessageType.MSG_HELLO
    data_back = json.loads(parsed.payload)
    assert data_back['name'] == 'BSH-Client'
    print(f"Parsed   : {parsed}  ✓")

    # Checksum tamper test
    bad = bytearray(wire)
    bad[-1] ^= 0xFF           # flip all bits of the checksum byte
    assert BSHPacket.from_bytes(bytes(bad)) is None, "Tampered packet should be rejected!"
    print("Checksum tamper rejected  ✓")

    # Window size round-trip
    ws = create_window_size_packet(48, 132)
    rows, cols = parse_window_size(BSHPacket.from_bytes(ws.to_bytes()))
    assert (rows, cols) == (48, 132)
    print(f"Window size {rows}×{cols}  ✓")

    # Unknown message type handling
    raw = bytearray(wire)
    raw[3] = 0xFF             # invalid type byte
    # recalculate checksum so it passes that check
    cs = raw[1] ^ raw[2] ^ raw[3]
    for b in raw[4:-1]:
        cs ^= b
    raw[-1] = cs & 0xFF
    assert BSHPacket.from_bytes(bytes(raw)) is None, "Unknown type should be rejected!"
    print("Unknown message type rejected  ✓")

    print("\nAll tests passed ✓")
    sys.exit(0)
