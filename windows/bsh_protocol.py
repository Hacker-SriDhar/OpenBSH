#!/usr/bin/env python3
# Copyright 2026 SRI DHARANIVEL A M
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
    Client → MSG_AUTH_LOGIN              {username, password (plaintext inside BT link)}
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
    MSG_AUTH_LOGIN     = 0x09   # Client → Server: username and plaintext password

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

        payload            = data[4:4 + length]
        received_checksum  = data[4 + length]

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

    hello = create_hello_packet({'name': 'BSH-Host', 'version': '1.0', 'os': 'Windows'})
    print(f"Created  : {hello}")
    print(f"Wire hex : {hello.to_bytes().hex()}")

    parsed = BSHPacket.from_bytes(hello.to_bytes())
    assert parsed is not None, "Parse failed!"
    print(f"Parsed   : {parsed}")
    print(f"Payload  : {json.loads(parsed.payload)}")
    print()

    data = create_data_packet("dir\r\n")
    print(f"Data pkt : {data}")
   
    ws = create_window_size_packet(24, 80)
    rows, cols = parse_window_size(ws)
    print(f"Win size : {rows}×{cols}")

    print("\nAll packet tests passed ✓")
