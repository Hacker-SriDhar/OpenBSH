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
BSH Linux Client — Bluetooth Shell client for Linux.

Connects to BOTH Linux BSH servers and Windows BSH servers.

Usage
─────
    python3 bsh_client_linux.py alice@AA:BB:CC:DD:EE:FF
    python3 bsh_client_linux.py alice@AA:BB:CC:DD:EE:FF -p 1

Features
────────
  • Native Python socket.AF_BLUETOOTH RFCOMM (stdlib, no PyBluez required)
  • SDP auto-discovery via PyBluez (optional) → sdptool fallback → manual entry
  • Terminal raw mode via termios / tty
  • Char-by-char forwarding — the remote PTY line discipline handles editing
  • SIGWINCH handler: propagates terminal resize to the remote shell in real-time
  • AES-256-GCM session encryption
  • Ctrl+C → MSG_INTERRUPT, Ctrl+D → MSG_DISCONNECT

Compatible servers
──────────────────
  • BSH Linux server   (bsh_server_service.py — Linux port)   ← PTY session
  • BSH Windows server (bsh_server_service.py — Windows port) ← cmd.exe session
"""

import sys
import os
import threading
import select
import signal
import json
import getpass
import termios
import tty
import queue
import struct
from typing import Optional, Tuple
import socket

# ─────────────────────────────────────────────────────────────────────────────
# Linux guard
# ─────────────────────────────────────────────────────────────────────────────
if sys.platform == 'win32':
    print("Error: bsh_client_linux.py must be run on Linux.")
    print("For Windows, use: python bsh_client_windows.py")
    sys.exit(1)

from bsh_protocol import (
    BSHPacket, MessageType,
    create_hello_packet, create_data_packet, create_window_size_packet,
)
from bsh_crypto import BSHCrypto

# Ignore top-level SIGINT — the session loop handles Ctrl+C
signal.signal(signal.SIGINT, signal.SIG_IGN)


# ─────────────────────────────────────────────────────────────────────────────
# Bluetooth constants (Python stdlib)
# ─────────────────────────────────────────────────────────────────────────────

AF_BLUETOOTH  = socket.AF_BLUETOOTH
BTPROTO_RFCOMM = socket.BTPROTO_RFCOMM


# ─────────────────────────────────────────────────────────────────────────────
# SDP Discovery
# ─────────────────────────────────────────────────────────────────────────────

BSH_SERVICE_UUID = "B5E7DA7A-0B53-1000-8000-00805F9B34FB"
SPP_UUID         = "00001101-0000-1000-8000-00805F9B34FB"


def _sdp_find_channel_pybluez(host_mac: str) -> Optional[int]:
    """Query SDP via PyBluez (preferred)."""
    try:
        import bluetooth as bt                           # pip install PyBluez
        # Try the BSH-specific UUID first
        services = bt.find_service(address=host_mac, uuid=BSH_SERVICE_UUID)
        if not services:
            # Fall back to the generic SPP UUID (works with Windows BSH)
            services = bt.find_service(address=host_mac, uuid=SPP_UUID)
        if services:
            ch = services[0].get('port')
            if ch:
                return int(ch)
    except ImportError:
        pass
    except Exception:
        pass
    return None


def _sdp_find_channel_sdptool(host_mac: str) -> Optional[int]:
    """Query SDP via the 'sdptool' command-line tool (BlueZ utils)."""
    import subprocess
    try:
        r = subprocess.run(
            ['sdptool', 'browse', '--bdaddr', host_mac],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            line_l = line.lower()
            if 'rfcomm' in line_l and 'channel' in line_l:
                # e.g.  "  RFCOMM Channel: 1"
                parts = line.split(':')
                if len(parts) >= 2:
                    try:
                        return int(parts[-1].strip())
                    except ValueError:
                        pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _scan_rfcomm_channels(host_mac: str, channels=range(1, 13)) -> Optional[int]:
    """Brute-force scan RFCOMM channels 1–12."""
    print("  Trying channel scan (may take 15–30 seconds)…")
    for ch in channels:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        sock.settimeout(3)
        try:
            sock.connect((host_mac, ch))
            sock.close()
            print(f"  ✓ Channel {ch} responded")
            return ch
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return None


def find_bsh_channel(host_mac: str) -> int:
    """Auto-discover the BSH RFCOMM channel: PyBluez SDP → sdptool → scan → manual."""
    print(f"  Discovering BSH service on {host_mac}…")

    ch = _sdp_find_channel_pybluez(host_mac)
    if ch:
        print(f"  ✓ Found on channel {ch} (PyBluez SDP)")
        return ch

    print("  PyBluez SDP failed — trying sdptool…")
    ch = _sdp_find_channel_sdptool(host_mac)
    if ch:
        print(f"  ✓ Found on channel {ch} (sdptool)")
        return ch

    print("  sdptool failed — trying channel scan…")
    ch = _scan_rfcomm_channels(host_mac)
    if ch:
        print(f"  ✓ Found on channel {ch} (scan)")
        return ch

    print("  Channel scan produced no result.")
    try:
        val = input("  Enter RFCOMM channel manually [1]: ").strip()
        return int(val) if val else 1
    except (ValueError, EOFError):
        print("  Defaulting to channel 1")
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Terminal size helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_terminal_size() -> Tuple[int, int]:
    """Return (rows, cols) from the controlling terminal."""
    try:
        import fcntl
        TIOCGWINSZ = termios.TIOCGWINSZ if hasattr(termios, 'TIOCGWINSZ') else 0x5413
        buf = struct.pack('HHHH', 0, 0, 0, 0)
        result = __import__('fcntl').ioctl(sys.stdout.fileno(), TIOCGWINSZ, buf)
        rows, cols, _, _ = struct.unpack('HHHH', result)
        if rows > 0 and cols > 0:
            return rows, cols
    except Exception:
        pass
    # Fallback via stty
    try:
        r, c = os.popen('stty size', 'r').read().split()
        return int(r), int(c)
    except Exception:
        return 24, 80


# ─────────────────────────────────────────────────────────────────────────────
# BSH Linux Client
# ─────────────────────────────────────────────────────────────────────────────

class BSHLinuxClient:
    """
    BSH client for Linux.

    Uses the Python stdlib AF_BLUETOOTH RFCOMM socket and terminal raw mode
    to provide a transparent PTY experience. Compatible with both Linux and
    Windows BSH servers.

    When connecting to a Linux server (PTY-based):
      → char-by-char forwarding; remote PTY handles echo and line editing.

    When connecting to a Windows server (cmd.exe):
      → same char-by-char path (the Windows server does its own line-buffering
        or echoes characters individually through cmd.exe).
    """

    def __init__(self, username: str):
        self.username      = username
        self.crypto        = BSHCrypto()
        self.sock          = None
        self.host_addr     = None
        self.authenticated = False
        self.session_key   = None
        self._send_lock    = threading.Lock()
        self._server_os    = 'unknown'   # populated from MSG_HELLO

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self, host_mac: str, channel: int) -> bool:
        self.host_addr = host_mac

        print(f"  Connecting to {host_mac} on RFCOMM channel {channel}…")
        self.sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        self.sock.settimeout(15)
        self.sock.connect((host_mac, channel))
        self.sock.settimeout(None)
        print(f"  ✓ RFCOMM connection established")

        # ── BSH handshake ─────────────────────────────────────────────────────
        self.send_packet(create_hello_packet({
            'name':        'BSH-Linux-Client',
            'version':     '1.0',
            'auth_method': 'password',
            'username':    self.username,
        }))

        server_hello = self.receive_packet()
        if not server_hello or server_hello.msg_type != MessageType.MSG_HELLO:
            raise RuntimeError("Invalid server handshake — not a BSH server?")

        hello_data        = json.loads(server_hello.payload.decode())
        self._server_os   = hello_data.get('os', 'unknown')
        features          = hello_data.get('features', [])
        print(
            f"  Connected to {hello_data.get('name', 'BSH Server')} "
            f"(OS: {self._server_os}, features: {', '.join(features)})"
        )
        if 'password' not in features:
            raise RuntimeError("Server does not support password authentication.")

        self._authenticate_password()
        return self.authenticated

    # ── Password authentication ───────────────────────────────────────────────

    # ── Password authentication ───────────────────────────────────────────────

    def _authenticate_password(self) -> None:
        """Single-step authentication sending username and password directly."""
        password = getpass.getpass(f"{self.username}'s password: ")

        # 1. Construct and send MSG_AUTH_LOGIN packet
        payload = json.dumps({
            'username': self.username,
            'password': password
        }).encode('utf-8')
        
        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_LOGIN, 
            payload
        ))

        # 2. Wait for server response
        result = self.receive_packet()
        
        if not result:
            raise RuntimeError("Connection dropped during authentication.")

        # 3. Handle Success or Failure
        if result.msg_type == MessageType.MSG_AUTH_SUCCESS:
            self.authenticated = True
            data = json.loads(result.payload.decode('utf-8'))
            if 'session_key' in data:
                self.session_key = bytes.fromhex(data['session_key'])
                print("  ✓ Session key established (AES-256-GCM)")
                
        elif result.msg_type == MessageType.MSG_AUTH_FAILURE:
            data = json.loads(result.payload.decode('utf-8'))
            error_msg = data.get('error', 'Permission denied')
            raise RuntimeError(error_msg)
            
        else:
            raise RuntimeError(f"Unexpected response during authentication: {result.msg_type}")
            
    # ── Interactive session ───────────────────────────────────────────────────

    def start_interactive_session(self) -> None:
        """
        Run the interactive shell session.

        Strategy: CHAR-BY-CHAR RAW MODE
        ────────────────────────────────
        Linux terminal raw mode passes every keystroke straight through to the
        server.  When connected to a Linux server the remote PTY's line
        discipline handles echo, backspace, and line editing perfectly — the
        experience is identical to an SSH session.

        When connected to a Windows server the raw bytes still reach cmd.exe
        and work correctly because the Windows server has its own line-buffering
        layer in PlainWindowsShell.
        """
        stop   = threading.Event()
        send_q = queue.Queue()

        stdin_fd  = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()

        # ── Window size ───────────────────────────────────────────────────────
        rows, cols = _get_terminal_size()
        self.send_packet(create_window_size_packet(rows, cols))

        def handle_resize(signum, frame):
            try:
                r, c = _get_terminal_size()
                send_q.put(create_window_size_packet(r, c))
            except Exception:
                pass

        signal.signal(signal.SIGWINCH, handle_resize)

        # ── Send loop ─────────────────────────────────────────────────────────
        def send_loop():
            while not stop.is_set():
                try:
                    packet = send_q.get(timeout=0.5)
                    self.send_packet(packet)
                except queue.Empty:
                    # Send a keepalive every ~5 s (10 × 0.5 s timer fires)
                    pass
                except Exception:
                    stop.set()
                    break

        # Keepalive fires from a separate lightweight timer thread.
        # Send every 0.5 s — matching the server's settimeout(0.5) so we never
        # hit the timeout between keepalives and trigger a spurious disconnect.
        def keepalive_loop():
            while not stop.is_set():
                threading.Event().wait(0.5)
                if stop.is_set():
                    break
                try:
                    send_q.put(BSHPacket(MessageType.MSG_KEEPALIVE))
                except Exception:
                    pass

        # ── Receive loop ──────────────────────────────────────────────────────
        def recv_loop():
            while not stop.is_set():
                try:
                    packet = self.receive_packet()
                    if not packet:
                        os.write(stdout_fd, b"\r\nConnection closed by remote host\r\n")
                        stop.set()
                        break

                    if packet.msg_type == MessageType.MSG_DATA_OUT:
                        os.write(stdout_fd, packet.payload)

                    elif packet.msg_type == MessageType.MSG_DATA_ERR:
                        os.write(sys.stderr.fileno(), packet.payload)

                    elif packet.msg_type == MessageType.MSG_DISCONNECT:
                        os.write(stdout_fd, b"\r\nConnection closed by remote host\r\n")
                        stop.set()
                        break

                except socket.timeout:
                    continue
                except Exception:
                    if not stop.is_set():
                        stop.set()
                    break

        t_send = threading.Thread(target=send_loop,      daemon=True, name='bsh-send')
        t_recv = threading.Thread(target=recv_loop,      daemon=True, name='bsh-recv')
        t_ka   = threading.Thread(target=keepalive_loop, daemon=True, name='bsh-ka')

        t_send.start()
        t_recv.start()
        t_ka.start()

        # ── stdin raw mode ────────────────────────────────────────────────────
        old_tty = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)

        try:
            is_windows = self._server_os.lower() == 'windows'
            win_buffer = bytearray()
            win_history = []
            win_history_idx = 0
            esc_seq = bytearray()
            
            while not stop.is_set():
                r, _, _ = select.select([stdin_fd], [], [], 0.1)
                if not r:
                    continue

                try:
                    data = os.read(stdin_fd, 128)
                except OSError:
                    break
                if not data:
                    break

                i = 0
                while i < len(data):
                    byte = data[i]

                    # ── Ctrl+D — disconnect ────────────────────────────────
                    if byte == 0x04:
                        send_q.put(BSHPacket(MessageType.MSG_DISCONNECT))
                        stop.set()
                        break

                    # ── Ctrl+C — send SIGINT to remote shell ───────────────
                    elif byte == 0x03:
                        if is_windows:
                            win_buffer.clear()
                            os.write(stdout_fd, b'^C\r\n')
                        send_q.put(BSHPacket(MessageType.MSG_INTERRUPT))
                        i += 1
                        continue

                    if not is_windows:
                        send_q.put(BSHPacket(MessageType.MSG_DATA_IN, bytes([byte])))
                        i += 1
                        continue
                        
                    # ── WINDOWS LOCAL LINE EDITING ────────────────────────
                    if len(esc_seq) > 0:
                        esc_seq.append(byte)
                        if len(esc_seq) == 2 and byte != 0x5b:
                            esc_seq.clear()
                        elif len(esc_seq) == 3 and byte in b'ABCD':
                            if esc_seq == b'\x1b[A': # Up
                                if win_history_idx > 0:
                                    if win_buffer:
                                        num_chars = len(win_buffer.decode('utf-8', 'replace'))
                                        os.write(stdout_fd, b'\x08' * num_chars + b'\x1b[K')
                                    win_history_idx -= 1
                                    win_buffer = bytearray(win_history[win_history_idx])
                                    if win_buffer:
                                        os.write(stdout_fd, bytes(win_buffer))
                            elif esc_seq == b'\x1b[B': # Down
                                if win_history_idx < len(win_history):
                                    if win_buffer:
                                        num_chars = len(win_buffer.decode('utf-8', 'replace'))
                                        os.write(stdout_fd, b'\x08' * num_chars + b'\x1b[K')
                                    win_history_idx += 1
                                    if win_history_idx == len(win_history):
                                        win_buffer = bytearray()
                                    else:
                                        win_buffer = bytearray(win_history[win_history_idx])
                                    if win_buffer:
                                        os.write(stdout_fd, bytes(win_buffer))
                            esc_seq.clear()
                        elif len(esc_seq) > 2 and 0x40 <= byte <= 0x7E:
                            esc_seq.clear()
                    elif byte == 0x1b:
                        esc_seq.append(byte)
                    elif byte == 0x08 or byte == 0x7f:
                        if len(win_buffer) > 0:
                            win_buffer.pop()
                            while len(win_buffer) > 0 and (win_buffer[-1] & 0xC0) == 0x80:
                                win_buffer.pop()
                            os.write(stdout_fd, b'\x08\x1b[K')
                    elif byte == 0x0d:
                        os.write(stdout_fd, b'\r\n')
                        if win_buffer:
                            if not win_history or win_history[-1] != win_buffer:
                                win_history.append(bytearray(win_buffer))
                        win_history_idx = len(win_history)
                        send_q.put(BSHPacket(MessageType.MSG_DATA_IN, bytes(win_buffer) + b'\r\n'))
                        win_buffer.clear()
                    else:
                        win_buffer.append(byte)
                        os.write(stdout_fd, bytes([byte]))
                    
                    i += 1

        finally:
            stop.set()
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)
            signal.signal(signal.SIGINT,   signal.SIG_DFL)

            # Close socket to immediately unblock recv_loop
            try:
                self.sock.close()
                self.sock = None
            except Exception:
                pass

            for t in (t_send, t_recv, t_ka):
                t.join(timeout=1.0)

            # Restore terminal
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tty)
            print(f"\r\nConnection to {self.host_addr} closed.")

    # ── Packet I/O ────────────────────────────────────────────────────────────

    def send_packet(self, packet: BSHPacket) -> None:
        """Encrypt + send a packet."""
        if self.session_key:
            packet = BSHPacket(
                packet.msg_type,
                self.crypto.encrypt_data(self.session_key, packet.payload),
            )
        with self._send_lock:
            self.sock.send(packet.to_bytes())

    def receive_packet(self) -> Optional[BSHPacket]:
        """Receive and decrypt one packet."""
        header = self._recv_exact(4)
        if not header:
            return None
        length = (header[1] << 8) | header[2]
        rest   = self._recv_exact(length + 1)
        if not rest:
            return None
        packet = BSHPacket.from_bytes(header + rest)
        if packet and self.session_key and packet.payload:
            try:
                packet = BSHPacket(
                    packet.msg_type,
                    self.crypto.decrypt_data(self.session_key, packet.payload),
                )
            except Exception:
                pass
        return packet

    def _recv_exact(self, size: int) -> Optional[bytes]:
        data = b''
        while len(data) < size:
            try:
                chunk = self.sock.recv(size - len(data))
            except socket.timeout:
                raise
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        return data

    def disconnect(self) -> None:
        if self.sock:
            try:
                self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _parse_destination(dest: str) -> Tuple[str, str]:
    if '@' in dest:
        username, mac = dest.split('@', 1)
    else:
        mac      = dest
        username = os.getenv('USER', 'user')
    return username.strip(), mac.strip().upper()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='BSH Linux Client — Bluetooth Shell',
        usage='bsh_client_linux.py [user@]<MAC> [-p channel]',
    )
    parser.add_argument(
        'destination',
        metavar='[user@]<MAC>',
        help='Target device, e.g.  alice@AA:BB:CC:DD:EE:FF',
    )
    parser.add_argument(
        '--port', '-p', type=int, default=None,
        metavar='channel',
        help='RFCOMM channel (default: auto-discover via SDP)',
    )
    parser.add_argument(
        '--no-discover', action='store_true',
        help='Skip SDP/scan and default to channel 1',
    )
    args = parser.parse_args()

    username, mac = _parse_destination(args.destination)

    parts = mac.split(':')
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        parser.error(
            f"Invalid Bluetooth address: {mac!r}  (expected XX:XX:XX:XX:XX:XX)"
        )

    if args.port is not None:
        channel = args.port
    elif args.no_discover:
        channel = 1
    else:
        channel = find_bsh_channel(mac)

    print(f"\nBSH — Connecting as '{username}' to {mac} (channel {channel})")
    print("-" * 50)

    client = BSHLinuxClient(username)
    try:
        if client.connect(mac, channel):
            print("-" * 50)
            client.start_interactive_session()
        else:
            return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except RuntimeError as exc:
        print(f"\nbsh: {exc}", file=sys.stderr)
        return 255
    except Exception as exc:
        print(f"\nbsh: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        client.disconnect()
    return 0


if __name__ == '__main__':
    sys.exit(main())
