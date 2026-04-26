#!/usr/bin/env python3
"""
BSH Windows Client — Bluetooth Shell client for Windows.

Connects to BOTH Windows BSH servers and Linux BSH servers.

Usage
─────
    python bsh_client_windows.py alice@AA:BB:CC:DD:EE:FF
    python bsh_client_windows.py alice@AA:BB:CC:DD:EE:FF -p 1

Features
────────
  • Raw Winsock AF_BTH RFCOMM socket (no PyBluez required)
  • SDP auto-discovery → channel scan fallback → manual entry
  • Line-buffered local editor: full line echoed locally, sent on Enter
  • Full cursor movement: Left/Right/Home/End/Del, Ctrl+A/E/K
  • Command history: Up/Down arrows
  • ANSI escape processing via ENABLE_VIRTUAL_TERMINAL_PROCESSING
  • AES-256-GCM session encryption
  • Keepalive + automatic window resize packets

Compatible servers
──────────────────
  • BSH Windows server  (bsh_server_service.py — Windows port)
  • BSH Linux server    (bsh_server_service.py — Linux port)
"""

import sys
import os
import threading
import json
import getpass
import ctypes
import signal
from ctypes import wintypes
from typing import Optional, Tuple
import socket
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Windows guard
# ─────────────────────────────────────────────────────────────────────────────
if sys.platform != 'win32':
    print("Error: bsh_client_windows.py must be run on Windows.")
    print("For Linux, use: python3 bsh_client_linux.py")
    sys.exit(1)

import msvcrt

from bsh_protocol import (
    BSHPacket, MessageType,
    create_hello_packet, create_data_packet, create_window_size_packet,
)
from bsh_crypto import BSHCrypto

# Ignore SIGINT at the top level — Ctrl+C is handled inside the session loop
signal.signal(signal.SIGINT, signal.SIG_IGN)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Bluetooth constants & structures (ws2bth.h)
# ─────────────────────────────────────────────────────────────────────────────

AF_BTH      = 32   # Winsock2 AF_BTH
BTHPROTO_RFCOMM = 3

class _GUID(ctypes.Structure):
    _pack_   = 1
    _fields_ = [
        ('Data1', ctypes.c_ulong),
        ('Data2', ctypes.c_ushort),
        ('Data3', ctypes.c_ushort),
        ('Data4', ctypes.c_ubyte * 8),
    ]

class _SOCKADDR_BTH(ctypes.Structure):
    _pack_   = 1
    _fields_ = [
        ('addressFamily',  ctypes.c_ushort),
        ('btAddr',         ctypes.c_ulonglong),
        ('serviceClassId', _GUID),
        ('port',           ctypes.c_ulong),
    ]

# Serial Port Profile GUID: {00001101-0000-1000-8000-00805F9B34FB}
_SPP_GUID        = _GUID()
_SPP_GUID.Data1  = 0x00001101
_SPP_GUID.Data2  = 0x0000
_SPP_GUID.Data3  = 0x1000
_SPP_GUID.Data4  = (_SPP_GUID.Data4._type_ * 8)(
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
)


def _bt_mac_to_int(mac: str) -> int:
    """Convert 'AA:BB:CC:DD:EE:FF' to a Windows btAddr integer."""
    result = 0
    for p in mac.split(':'):
        result = (result << 8) | int(p, 16)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# SDP Service Discovery (Windows WSA)
# ─────────────────────────────────────────────────────────────────────────────

_LUP_FLUSHCACHE  = 0x1000
_LUP_RETURN_ADDR = 0x0100
_LUP_RETURN_BLOB = 0x0200
_NS_BTH          = 16

class _BLOB(ctypes.Structure):
    _fields_ = [
        ('cbSize',    wintypes.ULONG),
        ('pBlobData', ctypes.POINTER(ctypes.c_ubyte)),
    ]

class _WSAQUERYSET(ctypes.Structure):
    _fields_ = [
        ('dwSize',                  wintypes.DWORD),
        ('lpszServiceInstanceName', wintypes.LPWSTR),
        ('lpServiceClassId',        ctypes.POINTER(_GUID)),
        ('lpVersion',               ctypes.c_void_p),
        ('lpszComment',             wintypes.LPWSTR),
        ('dwNameSpace',             wintypes.DWORD),
        ('lpNSProviderId',          ctypes.c_void_p),
        ('lpszContext',             wintypes.LPWSTR),
        ('dwNumberOfProtocols',     wintypes.DWORD),
        ('lpafpProtocols',          ctypes.c_void_p),
        ('lpszQueryString',         wintypes.LPWSTR),
        ('dwNumberOfCsAddrs',       wintypes.DWORD),
        ('lpcsaBuffer',             ctypes.c_void_p),
        ('dwOutputFlags',           wintypes.DWORD),
        ('lpBlob',                  ctypes.POINTER(_BLOB)),
    ]


def _sdp_find_rfcomm_channel(host_mac: str) -> Optional[int]:
    """Query the remote device's SDP database for an RFCOMM channel."""
    ws2_32     = ctypes.windll.ws2_32
    bt_context = f"({host_mac})"

    # BSH Service UUID
    svc_guid        = _GUID()
    svc_guid.Data1  = 0xB5E7DA7A
    svc_guid.Data2  = 0x0B53
    svc_guid.Data3  = 0x1000
    svc_guid.Data4  = (svc_guid.Data4._type_ * 8)(
        0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
    )

    qs                  = _WSAQUERYSET()
    qs.dwSize           = ctypes.sizeof(_WSAQUERYSET)
    qs.lpServiceClassId = ctypes.pointer(svc_guid)
    qs.dwNameSpace      = _NS_BTH
    qs.lpszContext      = bt_context

    flags  = _LUP_FLUSHCACHE | _LUP_RETURN_ADDR | _LUP_RETURN_BLOB
    handle = ctypes.c_void_p()

    ret = ws2_32.WSALookupServiceBeginW(ctypes.byref(qs), flags, ctypes.byref(handle))
    if ret != 0:
        return None

    channel  = None
    buf_size = wintypes.DWORD(8192)
    buf      = ctypes.create_string_buffer(8192)

    while True:
        buf_size.value = 8192
        ret = ws2_32.WSALookupServiceNextW(handle, flags, ctypes.byref(buf_size), buf)
        if ret != 0:
            break
        result = ctypes.cast(buf, ctypes.POINTER(_WSAQUERYSET)).contents
        if result.dwNumberOfCsAddrs > 0 and result.lpcsaBuffer:
            try:
                csa_raw   = ctypes.cast(result.lpcsaBuffer, ctypes.POINTER(ctypes.c_ulonglong))
                remote_sa = ctypes.cast(csa_raw[2], ctypes.POINTER(_SOCKADDR_BTH))
                ch        = int(remote_sa.contents.port)
                if ch > 0:
                    channel = ch
                    break
            except Exception:
                pass

    ws2_32.WSALookupServiceEnd(handle)
    return channel


def _scan_rfcomm_channels(host_mac: str, channels=range(1, 13)) -> Optional[int]:
    """Brute-force scan RFCOMM channels 1–12 to find the one BSH is listening on."""
    print("  Trying channel scan (this may take 10–30 seconds)…")
    for ch in channels:
        sock = socket.socket(AF_BTH, socket.SOCK_STREAM, BTHPROTO_RFCOMM)
        sock.settimeout(3)
        try:
            _win_connect_rfcomm(sock, host_mac, ch)
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
    """Auto-discover the BSH RFCOMM channel: SDP → scan → manual entry."""
    print(f"  Discovering BSH service on {host_mac} via SDP…")
    channel = _sdp_find_rfcomm_channel(host_mac)
    if channel:
        print(f"  ✓ Found on channel {channel} (SDP)")
        return channel

    channel = _scan_rfcomm_channels(host_mac)
    if channel:
        print(f"  ✓ Found on channel {channel} (scan)")
        return channel

    print("  Channel scan failed.")
    try:
        channel = int(input("  Enter RFCOMM channel manually [1]: ").strip() or "1")
        return channel
    except (ValueError, EOFError):
        print("  Defaulting to channel 1")
        return 1


def _win_connect_rfcomm(sock: socket.socket, host_mac: str, channel: int) -> None:
    """Connect a raw Winsock AF_BTH socket to *host_mac* on RFCOMM *channel*."""
    addr                = _SOCKADDR_BTH()
    addr.addressFamily  = AF_BTH
    addr.btAddr         = _bt_mac_to_int(host_mac)
    addr.serviceClassId = _SPP_GUID
    addr.port           = channel

    ws2_32 = ctypes.windll.ws2_32
    ret    = ws2_32.connect(sock.fileno(), ctypes.byref(addr), ctypes.sizeof(addr))
    if ret != 0:
        err   = ws2_32.WSAGetLastError()
        hints = {
            10013: "WSAEACCES — run as Administrator",
            10047: "WSAEAFNOSUPPORT — Bluetooth adapter not available",
            10061: "WSAECONNREFUSED — host refused connection (wrong channel?)",
            10060: "WSAETIMEDOUT — host unreachable or not advertising",
            10022: "WSAEINVAL — invalid Bluetooth address format",
        }
        raise OSError(
            f"Winsock connect() failed: WSAError {err} ({hints.get(err, 'unknown error')})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Windows Console helpers
# ─────────────────────────────────────────────────────────────────────────────

ENABLE_ECHO_INPUT                 = 0x0004
ENABLE_LINE_INPUT                 = 0x0002
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004   # stdout flag


class WindowsConsole:
    """Manages Windows console raw mode and ANSI VT processing."""

    def __init__(self):
        k32               = ctypes.windll.kernel32
        self._k32         = k32
        self._stdin_h     = k32.GetStdHandle(-10)   # STD_INPUT_HANDLE
        self._stdout_h    = k32.GetStdHandle(-11)   # STD_OUTPUT_HANDLE
        self._old_in      = ctypes.c_ulong(0)
        self._old_out     = ctypes.c_ulong(0)

    def set_raw(self) -> None:
        """Disable echo + line buffering; enable ANSI escapes on stdout."""
        self._k32.GetConsoleMode(self._stdin_h,  ctypes.byref(self._old_in))
        self._k32.GetConsoleMode(self._stdout_h, ctypes.byref(self._old_out))

        new_in  = self._old_in.value  & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)
        new_out = self._old_out.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING

        self._k32.SetConsoleMode(self._stdin_h,  new_in)
        self._k32.SetConsoleMode(self._stdout_h, new_out)

    def restore(self) -> None:
        """Restore original console modes."""
        self._k32.SetConsoleMode(self._stdin_h,  self._old_in)
        self._k32.SetConsoleMode(self._stdout_h, self._old_out)

    def get_size(self) -> Tuple[int, int]:
        """Return (rows, cols) of the console window."""
        class COORD(ctypes.Structure):
            _fields_ = [('X', ctypes.c_short), ('Y', ctypes.c_short)]
        class SMALL_RECT(ctypes.Structure):
            _fields_ = [
                ('Left',   ctypes.c_short), ('Top',    ctypes.c_short),
                ('Right',  ctypes.c_short), ('Bottom', ctypes.c_short),
            ]
        class CSBI(ctypes.Structure):
            _fields_ = [
                ('dwSize',              COORD),
                ('dwCursorPosition',    COORD),
                ('wAttributes',         ctypes.c_ushort),
                ('srWindow',            SMALL_RECT),
                ('dwMaximumWindowSize', COORD),
            ]
        info = CSBI()
        self._k32.GetConsoleScreenBufferInfo(self._stdout_h, ctypes.byref(info))
        cols = info.srWindow.Right  - info.srWindow.Left + 1
        rows = info.srWindow.Bottom - info.srWindow.Top  + 1
        return rows, cols


# ─────────────────────────────────────────────────────────────────────────────
# BSH Windows Client
# ─────────────────────────────────────────────────────────────────────────────

class BSHWindowsClient:
    """
    BSH client for Windows.

    Uses raw Winsock AF_BTH RFCOMM and a local line-editor with history.
    Compatible with both Windows and Linux BSH servers.
    """

    def __init__(self, username: str):
        self.username      = username
        self.crypto        = BSHCrypto()
        self.sock          = None
        self.host_addr     = None
        self.authenticated = False
        self.session_key   = None
        self._send_lock    = threading.Lock()
        self._console      = WindowsConsole()
        self._server_os    = 'unknown'   # set from MSG_HELLO; controls local echo

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self, host_mac: str, channel: int) -> bool:
        self.host_addr = host_mac
        self.sock      = socket.socket(AF_BTH, socket.SOCK_STREAM, BTHPROTO_RFCOMM)

        print(f"  Connecting to {host_mac} on RFCOMM channel {channel}…")
        _win_connect_rfcomm(self.sock, host_mac, channel)
        print(f"  ✓ TCP handshake complete")

        # Use a timeout for the handshake so we don't hang forever if the server is stuck
        self.sock.settimeout(5.0)

        # ── BSH handshake ─────────────────────────────────────────────────────
        try:
            self.send_packet(create_hello_packet({
                'name':        'BSH-Windows-Client',
                'version':     '1.0',
                'auth_method': 'password',
                'username':    self.username,
            }))

            server_hello = self.receive_packet()
        except socket.timeout:
            raise RuntimeError("Handshake timed out. The server accepted the connection but did not respond. It might be stuck from a previous session.")
        except Exception as e:
            raise RuntimeError(f"Handshake failed: {e}")

        if not server_hello or server_hello.msg_type != MessageType.MSG_HELLO:
            raise RuntimeError("Invalid server handshake — not a BSH server?")

        hello_data        = json.loads(server_hello.payload.decode())
        self._server_os   = hello_data.get('os', 'unknown')
        features          = hello_data.get('features', [])
        print(f"  Connected to {hello_data.get('name', 'BSH Server')} "
              f"(OS: {self._server_os}, features: {', '.join(features)})")

        if 'password' not in features:
            raise RuntimeError("Server does not support password authentication.")

        try:
            self._authenticate_password()
        except socket.timeout:
            raise RuntimeError("Authentication timed out. The server stopped responding.")
        
        # Remove the timeout for the interactive session
        self.sock.settimeout(None)
        
        return self.authenticated

    # ── Password authentication ───────────────────────────────────────────────

    def _authenticate_password(self) -> None:
        password = getpass.getpass(f"{self.username}'s password: ")

        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_PASSWORD_REQUEST,
            json.dumps({}).encode(),
        ))

        challenge_pkt = self.receive_packet()
        if not challenge_pkt:
            raise RuntimeError("No response to password auth request")
        if challenge_pkt.msg_type == MessageType.MSG_AUTH_FAILURE:
            raise RuntimeError(json.loads(challenge_pkt.payload).get('error', 'Auth failed'))
        if challenge_pkt.msg_type != MessageType.MSG_AUTH_PASSWORD_CHALLENGE:
            raise RuntimeError(f"Unexpected packet: {challenge_pkt.msg_type}")

        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_PASSWORD_RESPONSE,
            json.dumps({'password': password}).encode(),
        ))

        result = self.receive_packet()
        if result and result.msg_type == MessageType.MSG_AUTH_SUCCESS:
            self.authenticated = True
            data = json.loads(result.payload.decode())
            if 'session_key' in data:
                self.session_key = bytes.fromhex(data['session_key'])
                print("  ✓ Session key established (AES-256-GCM)")
        elif result and result.msg_type == MessageType.MSG_AUTH_FAILURE:
            raise RuntimeError(json.loads(result.payload).get('error', 'Permission denied'))
        else:
            raise RuntimeError("Unexpected response during authentication")

    # ── Interactive session ───────────────────────────────────────────────────

    def start_interactive_session(self) -> None:
        """
        Run the interactive shell session.

        Strategy: CLIENT-SIDE LINE BUFFERING
        ─────────────────────────────────────
        Windows servers (cmd.exe / no PTY):
          Each character is echoed locally as it is typed.  The completed line
          is sent to the server on Enter.  The server's echo of the command is
          suppressed (we already showed it locally).

        Linux servers (PTY-based):
          Local echo is DISABLED.  The remote PTY line discipline echoes each
          character back via MSG_DATA_OUT — just like an SSH session.  Echoing
          locally as well would cause every character to appear twice.
        """
        _pty_server = self._server_os.lower() == 'linux'  # True → remote PTY echoes
        console = self._console
        console.set_raw()

        rows, cols = console.get_size()
        self.send_packet(create_window_size_packet(rows, cols))

        stop        = threading.Event()
        stdout_lock = threading.Lock()
        last_sent   = ['']   # for echo suppression of the command we sent

        # DEBUG LOGGING SETUP
        debug_log = open("client_debug.log", "w", encoding="utf-8")
        def _debug(msg):
            debug_log.write(f"{msg}\n")
            debug_log.flush()
        _debug("Session started.")

        # Use a socket timeout so recv doesn't block forever on Windows RFCOMM
        # (select.select does NOT work reliably on AF_BTH sockets)
        self.sock.settimeout(0.2)

        # ── Receive loop ──────────────────────────────────────────────────────
        def recv_loop():
            while not stop.is_set():
                try:
                    packet = self.receive_packet()
                    if not packet:
                        with stdout_lock:
                            sys.stdout.write("\r\nConnection closed by remote host\r\n")
                            sys.stdout.flush()
                        stop.set()
                        break

                    if packet.msg_type == MessageType.MSG_DATA_OUT:
                        data = packet.payload.decode('utf-8', errors='replace')
                        _debug(f"RECV: {repr(data)}")
                        if not _pty_server:
                            # Windows server: suppress echo of the line we already showed locally
                            cmd = last_sent[0]
                            if cmd:
                                lines = data.split('\n')
                                out_lines, suppressed = [], False
                                for line in lines:
                                    if not suppressed and line.strip('\r ') == cmd.strip():
                                        suppressed = True
                                        last_sent[0] = ''
                                    else:
                                        out_lines.append(line)
                                data = '\n'.join(out_lines)
                                if not data.strip('\r\n'):
                                    continue
                        with stdout_lock:
                            sys.stdout.write(data)
                            sys.stdout.flush()

                    elif packet.msg_type == MessageType.MSG_DISCONNECT:
                        with stdout_lock:
                            sys.stdout.write("\r\nConnection closed by remote host\r\n")
                            sys.stdout.flush()
                        stop.set()
                        break

                except socket.timeout:
                    continue
                except Exception as exc:
                    if not stop.is_set():
                        with stdout_lock:
                            sys.stdout.write(f"\r\nReceive error: {exc}\r\n")
                            sys.stdout.flush()
                    stop.set()
                    break

        # ── Background: keepalive + window-resize ────────────────────────────
        last_size = [console.get_size()]

        def background_loop():
            while not stop.is_set():
                threading.Event().wait(0.5)
                if stop.is_set():
                    break
                try:
                    self.send_packet(BSHPacket(MessageType.MSG_KEEPALIVE))
                except Exception:
                    pass
                size = console.get_size()
                if size != last_size[0]:
                    last_size[0] = size
                    try:
                        self.send_packet(create_window_size_packet(*size))
                    except Exception:
                        pass

        # ── Local line editor ─────────────────────────────────────────────────
        def redraw_line(buf, cursor):
            """Redraw the current input line in-place."""
            with stdout_lock:
                line_str = ''.join(buf)
                sys.stdout.write('\r\x1b[K' + line_str)
                if cursor < len(buf):
                    sys.stdout.write(f'\x1b[{len(buf) - cursor}D')
                sys.stdout.flush()

        def input_loop():
            buf      = []   # current line buffer
            cursor   = 0    # insertion index
            history  = []   # sent command history
            hist_pos = 0    # 0 = new input
            saved    = []   # saved draft while browsing history

            while not stop.is_set():
                try:
                    ch = msvcrt.getwch()

                    if _pty_server:
                        # ── PTY PASS-THROUGH MODE (Linux Servers) ───────────
                        if ch in ('\x00', '\xe0'):
                            ch2 = msvcrt.getwch()
                            seq = None
                            if ch2 == 'K': seq = '\x1b[D'    # Left
                            elif ch2 == 'M': seq = '\x1b[C'  # Right
                            elif ch2 == 'H': seq = '\x1b[A'  # Up
                            elif ch2 == 'P': seq = '\x1b[B'  # Down
                            elif ch2 == 'G': seq = '\x1b[H'  # Home
                            elif ch2 == 'O': seq = '\x1b[F'  # End
                            elif ch2 == 'S': seq = '\x1b[3~' # Delete
                            if seq:
                                self.send_packet(create_data_packet(seq, MessageType.MSG_DATA_IN))
                            continue
                        elif ch == '\x04': # Ctrl+D
                            self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
                            stop.set()
                            break
                        elif ch == '\x03': # Ctrl+C
                            self.send_packet(BSHPacket(MessageType.MSG_INTERRUPT))
                            continue
                        elif ch == '\r':
                            _debug("SEND: \\r")
                            self.send_packet(create_data_packet('\r', MessageType.MSG_DATA_IN))
                            continue
                        elif ch in ('\x08', '\x7f'): # Backspace
                            _debug("SEND: BACKSPACE")
                            self.send_packet(create_data_packet('\x7f', MessageType.MSG_DATA_IN))
                            continue
                        else:
                            _debug(f"SEND: {repr(ch)}")
                            self.send_packet(create_data_packet(ch, MessageType.MSG_DATA_IN))
                            continue

                    # ── WINDOWS LOCAL LINE EDITING (Windows Servers) ────────
                    if ch in ('\x00', '\xe0'):
                        ch2 = msvcrt.getwch()

                        if ch2 == 'K':      # Left arrow
                            if cursor > 0:
                                cursor -= 1
                                with stdout_lock:
                                    sys.stdout.write('\x1b[D'); sys.stdout.flush()

                        elif ch2 == 'M':    # Right arrow
                            if cursor < len(buf):
                                cursor += 1
                                with stdout_lock:
                                    sys.stdout.write('\x1b[C'); sys.stdout.flush()

                        elif ch2 == 'G':    # Home
                            if cursor > 0:
                                with stdout_lock:
                                    sys.stdout.write(f'\x1b[{cursor}D'); sys.stdout.flush()
                                cursor = 0

                        elif ch2 == 'O':    # End
                            if cursor < len(buf):
                                with stdout_lock:
                                    sys.stdout.write(f'\x1b[{len(buf)-cursor}C'); sys.stdout.flush()
                                cursor = len(buf)

                        elif ch2 == 'S':    # Delete key
                            if cursor < len(buf):
                                buf.pop(cursor)
                                tail = ''.join(buf[cursor:]) + ' '
                                with stdout_lock:
                                    sys.stdout.write(tail + f'\x1b[{len(tail)}D'); sys.stdout.flush()

                        elif ch2 == 'H':    # Up arrow — history previous
                            if history and hist_pos < len(history):
                                if hist_pos == 0:
                                    saved = buf[:]
                                hist_pos += 1
                                buf    = list(history[-hist_pos])
                                cursor = len(buf)
                                redraw_line(buf, cursor)

                        elif ch2 == 'P':    # Down arrow — history next
                            if hist_pos > 0:
                                hist_pos -= 1
                                buf    = saved[:] if hist_pos == 0 else list(history[-hist_pos])
                                cursor = len(buf)
                                redraw_line(buf, cursor)

                        continue

                    # ── Ctrl+D — disconnect ─────────────────────────────────
                    if ch == '\x04':
                        self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
                        stop.set()
                        break

                    # ── Ctrl+C — interrupt (send to remote shell) ───────────
                    elif ch == '\x03':
                        buf.clear(); cursor = 0; hist_pos = 0
                        with stdout_lock:
                            sys.stdout.write('^C\r\n'); sys.stdout.flush()
                        self.send_packet(BSHPacket(MessageType.MSG_INTERRUPT))

                    # ── Ctrl+A — jump to start ──────────────────────────────
                    elif ch == '\x01':
                        if cursor > 0:
                            with stdout_lock:
                                sys.stdout.write(f'\x1b[{cursor}D'); sys.stdout.flush()
                            cursor = 0

                    # ── Ctrl+E — jump to end ────────────────────────────────
                    elif ch == '\x05':
                        if cursor < len(buf):
                            with stdout_lock:
                                sys.stdout.write(f'\x1b[{len(buf)-cursor}C'); sys.stdout.flush()
                            cursor = len(buf)

                    # ── Ctrl+K — kill to end of line ────────────────────────
                    elif ch == '\x0b':
                        if cursor < len(buf):
                            killed = len(buf) - cursor
                            buf    = buf[:cursor]
                            with stdout_lock:
                                sys.stdout.write(' ' * killed + f'\x1b[{killed}D'); sys.stdout.flush()

                    # ── Enter — send line ───────────────────────────────────
                    elif ch == '\r':
                        line = ''.join(buf)
                        last_sent[0] = line
                        if line and (not history or history[-1] != line):
                            history.append(line)
                        buf = []; cursor = 0; hist_pos = 0; saved = []
                        with stdout_lock:
                            sys.stdout.write('\r\n'); sys.stdout.flush()
                        self.send_packet(create_data_packet(line + '\r\n', MessageType.MSG_DATA_IN))

                    # ── Backspace ───────────────────────────────────────────
                    elif ch in ('\x08', '\x7f'):
                        if cursor > 0:
                            buf.pop(cursor - 1)
                            cursor -= 1
                            tail = ''.join(buf[cursor:]) + ' '
                            with stdout_lock:
                                sys.stdout.write('\x08' + tail + f'\x1b[{len(tail)}D'); sys.stdout.flush()

                    # ── Printable character ─────────────────────────────────
                    elif ord(ch) >= 32:
                        buf.insert(cursor, ch)
                        cursor += 1
                        tail = ''.join(buf[cursor:])
                        with stdout_lock:
                            if tail:
                                sys.stdout.write(ch + tail + f'\x1b[{len(tail)}D')
                            else:
                                sys.stdout.write(ch)
                            sys.stdout.flush()

                    # ── Other control char — pass through ───────────────────
                    else:
                        self.send_packet(create_data_packet(ch, MessageType.MSG_DATA_IN))

                except KeyboardInterrupt:
                    buf.clear(); cursor = 0
                    self.send_packet(BSHPacket(MessageType.MSG_INTERRUPT))
                except Exception as exc:
                    if not stop.is_set():
                        with stdout_lock:
                            sys.stdout.write(f"\r\nInput error: {exc}\r\n"); sys.stdout.flush()
                    stop.set()
                    break

        # ── Start threads ─────────────────────────────────────────────────────
        t_recv = threading.Thread(target=recv_loop,       daemon=True, name='bsh-recv')
        t_bg   = threading.Thread(target=background_loop, daemon=True, name='bsh-bg')
        t_inp  = threading.Thread(target=input_loop,      daemon=True, name='bsh-input')

        t_recv.start()
        t_bg.start()
        t_inp.start()

        try:
            stop.wait()
        except KeyboardInterrupt:
            try:
                self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
            except Exception:
                pass
        finally:
            stop.set()
            try:
                self.sock.close()
                self.sock = None
            except Exception:
                pass
            for t in (t_recv, t_bg, t_inp):
                t.join(timeout=1.0)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            console.restore()
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
        username = os.getenv('USERNAME', 'user')
    return username.strip(), mac.strip().upper()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='BSH Windows Client — Bluetooth Shell',
        usage='bsh_client_windows.py [user@]<MAC> [-p channel]',
    )
    parser.add_argument(
        'destination',
        metavar='[user@]<MAC>',
        help='Target device, e.g.  alice@AA:BB:CC:DD:EE:FF',
    )
    parser.add_argument(
        '--port', '-p', type=int, default=None,
        metavar='channel',
        help='RFCOMM channel (default: auto-discover via SDP then scan)',
    )
    args = parser.parse_args()

    username, mac = _parse_destination(args.destination)

    parts = mac.split(':')
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        parser.error(
            f"Invalid Bluetooth address: {mac!r}  (expected XX:XX:XX:XX:XX:XX)"
        )

    channel = args.port or find_bsh_channel(mac)

    print(f"\nBSH — Connecting as '{username}' to {mac} (channel {channel})")
    print("-" * 50)

    client = BSHWindowsClient(username)
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
