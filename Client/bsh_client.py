#!/usr/bin/env python3
"""
BSH Client v3 - Cross-Platform, Password Authentication Only
Usage:
    bsh <username>@<MAC>              # auto-discover channel via SDP
    bsh <username>@<MAC> -p <port>    # specify RFCOMM channel

- Windows: Raw Winsock RFCOMM (no PyBluez), console raw mode via msvcrt + ctypes
           Line-buffered input: full line is sent on Enter, backspace is local only.
           Server echo of the command is suppressed (we already echoed locally).
- Linux:   Native AF_BLUETOOTH socket, terminal raw mode via termios/tty
           Char-by-char forwarding — Unix PTY line discipline handles everything.
"""

import sys
import os
import threading
import select
import json
import getpass
import ctypes
import hmac
import hashlib
from ctypes import wintypes
from typing import Optional, Tuple
import socket
from pathlib import Path

from bsh_protocol import (
    BSHPacket, MessageType,
    create_hello_packet, create_data_packet, create_window_size_packet
)
from bsh_crypto import BSHCrypto
import signal
signal.signal(signal.SIGINT, signal.SIG_IGN)  # ignore SIGINT — we handle Ctrl+C manually

# ──────────────────────────────────────────────
# Platform detection
# ──────────────────────────────────────────────
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX   = sys.platform.startswith('linux')

# ──────────────────────────────────────────────
# Bluetooth socket constants
# ──────────────────────────────────────────────
if IS_WINDOWS:
    AF_BT    = 32   # AF_BTH
    BT_PROTO = 3    # BTHPROTO_RFCOMM
else:
    AF_BT    = 31   # AF_BLUETOOTH
    BT_PROTO = 3    # BTPROTO_RFCOMM

# ──────────────────────────────────────────────
# Linux-only imports
# ──────────────────────────────────────────────
if IS_LINUX:
    import termios
    import tty
    import signal

# ──────────────────────────────────────────────
# Windows-only imports
# ──────────────────────────────────────────────
if IS_WINDOWS:
    import msvcrt


# ══════════════════════════════════════════════
# Windows SOCKADDR_BTH (ws2bth.h)
# ══════════════════════════════════════════════
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
    """'AA:BB:CC:DD:EE:FF'  →  integer (big-endian)"""
    parts = mac.split(':')
    result = 0
    for p in parts:
        result = (result << 8) | int(p, 16)
    return result

# ══════════════════════════════════════════════
# SDP Service Discovery
# ══════════════════════════════════════════════
_LUP_FLUSHCACHE  = 0x1000
_LUP_RETURN_ADDR = 0x0100
_LUP_RETURN_BLOB = 0x0200
_NS_BTH          = 16

class _BLOB(ctypes.Structure):
    _fields_ = [('cbSize', wintypes.ULONG), ('pBlobData', ctypes.POINTER(ctypes.c_ubyte))]

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
    if not IS_WINDOWS:
        return None

    ws2_32     = ctypes.windll.ws2_32
    bt_context = f"({host_mac})"

    svc_guid        = _GUID()
    svc_guid.Data1  = 0xBEA7DA7A
    svc_guid.Data2  = 0x0BEA
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
    print("  Trying channel scan (this may take 10-15 seconds)...")
    for ch in channels:
        try:
            sock = socket.socket(AF_BT, socket.SOCK_STREAM, BT_PROTO)
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
    print(f"  Discovering BSH service on {host_mac} via SDP...")
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
        channel = int(input("  Enter RFCOMM channel manually: ").strip())
        return channel
    except (ValueError, EOFError):
        print("  Defaulting to channel 4")
        return 4

def _win_connect_rfcomm(sock: socket.socket, host_mac: str, channel: int):
    addr = _SOCKADDR_BTH()
    addr.addressFamily  = AF_BT
    addr.btAddr         = _bt_mac_to_int(host_mac)
    addr.serviceClassId = _SPP_GUID
    addr.port           = channel

    ws2_32 = ctypes.windll.ws2_32
    ret    = ws2_32.connect(sock.fileno(), ctypes.byref(addr), ctypes.sizeof(addr))
    if ret != 0:
        err   = ws2_32.WSAGetLastError()
        hints = {
            10013: "WSAEACCES — run as Administrator",
            10047: "WSAEAFNOSUPPORT — Bluetooth not available",
            10061: "WSAECONNREFUSED — host refused (wrong channel?)",
            10060: "WSAETIMEDOUT — host unreachable / not advertising",
            10022: "WSAEINVAL — invalid address format",
        }
        raise OSError(f"Winsock connect() failed: WSAError {err} ({hints.get(err, 'unknown')})")


# ══════════════════════════════════════════════
# Windows console raw-mode helpers
# ══════════════════════════════════════════════
ENABLE_ECHO_INPUT = 0x0004
ENABLE_LINE_INPUT = 0x0002
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004  # stdout flag for ANSI escape processing

class WindowsConsole:
    def __init__(self):
        self._kernel32    = ctypes.windll.kernel32
        self._stdin_h     = self._kernel32.GetStdHandle(-10)   # STD_INPUT_HANDLE
        self._stdout_h    = self._kernel32.GetStdHandle(-11)   # STD_OUTPUT_HANDLE
        self._old_mode    = ctypes.c_ulong(0)
        self._old_out_mode = ctypes.c_ulong(0)

    def set_raw(self):
        # Disable echo + line buffering on stdin
        self._kernel32.GetConsoleMode(self._stdin_h, ctypes.byref(self._old_mode))
        new_mode = self._old_mode.value & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)
        self._kernel32.SetConsoleMode(self._stdin_h, new_mode)

        # Enable ANSI escape-sequence processing on stdout (Fix #3)
        self._kernel32.GetConsoleMode(self._stdout_h, ctypes.byref(self._old_out_mode))
        self._kernel32.SetConsoleMode(
            self._stdout_h,
            self._old_out_mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        )

    def restore(self):
        self._kernel32.SetConsoleMode(self._stdin_h,  self._old_mode)
        self._kernel32.SetConsoleMode(self._stdout_h, self._old_out_mode)

    def get_console_size(self) -> Tuple[int, int]:
        class COORD(ctypes.Structure):
            _fields_ = [('X', ctypes.c_short), ('Y', ctypes.c_short)]
        class SMALL_RECT(ctypes.Structure):
            _fields_ = [('Left',  ctypes.c_short), ('Top',    ctypes.c_short),
                        ('Right', ctypes.c_short), ('Bottom', ctypes.c_short)]
        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ('dwSize',              COORD),
                ('dwCursorPosition',    COORD),
                ('wAttributes',         ctypes.c_ushort),
                ('srWindow',            SMALL_RECT),
                ('dwMaximumWindowSize', COORD),
            ]
        stdout_h = self._kernel32.GetStdHandle(-11)
        info     = CONSOLE_SCREEN_BUFFER_INFO()
        self._kernel32.GetConsoleScreenBufferInfo(stdout_h, ctypes.byref(info))
        cols = info.srWindow.Right  - info.srWindow.Left + 1
        rows = info.srWindow.Bottom - info.srWindow.Top  + 1
        return rows, cols


# ══════════════════════════════════════════════
# BSH Client
# ══════════════════════════════════════════════
class BSHClient:

    def __init__(self, username: str):
        self.username      = username
        self.crypto        = BSHCrypto()
        self.sock          = None
        self.host_addr     = None
        self.authenticated = False
        self.session_key   = None
        self._send_lock    = threading.Lock()
        self._win_console  = WindowsConsole() if IS_WINDOWS else None
        self._old_tty      = None

    # ──────────────────────────────────────────
    # Connection + handshake
    # ──────────────────────────────────────────
    def connect(self, host_addr: str, port: int) -> bool:
        self.host_addr = host_addr
        self.sock = socket.socket(AF_BT, socket.SOCK_STREAM, BT_PROTO)

        if IS_WINDOWS:
            _win_connect_rfcomm(self.sock, host_addr, port)
        else:
            self.sock.connect((host_addr, port))

        self.send_packet(create_hello_packet({
            'name'       : 'BSH-Client',
            'version'    : '3.0',
            'auth_method': 'password',
            'username'   : self.username,
        }))

        server_hello = self.receive_packet()
        if not server_hello or server_hello.msg_type != MessageType.MSG_HELLO:
            raise RuntimeError("Invalid server handshake")

        hello_data    = json.loads(server_hello.payload.decode())
        server_name   = hello_data.get('name', 'BSH Server')
        auth_features = hello_data.get('features', [])

        print(f"Connected to {server_name} ({host_addr})")
        if auth_features:
            print(f"Features supported: {', '.join(auth_features)}")

        if 'password' not in auth_features:
            raise RuntimeError("Server does not support password authentication.")

        self._authenticate_password()
        return self.authenticated

    # ──────────────────────────────────────────
    # Password authentication
    # ──────────────────────────────────────────
    def _authenticate_password(self):
        password = getpass.getpass(f"{self.username}'s password: ")

        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_PASSWORD_REQUEST,
            json.dumps({}).encode()
        ))

        challenge_packet = self.receive_packet()
        if not challenge_packet:
            raise RuntimeError("No response to password auth request")
        if challenge_packet.msg_type == MessageType.MSG_AUTH_FAILURE:
            error = json.loads(challenge_packet.payload).get('error', 'Auth failed')
            raise RuntimeError(error)
        if challenge_packet.msg_type != MessageType.MSG_AUTH_PASSWORD_CHALLENGE:
            raise RuntimeError(f"Expected password challenge, got {challenge_packet.msg_type}")

        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_PASSWORD_RESPONSE,
            json.dumps({'password': password}).encode()
        ))

        result = self.receive_packet()
        if result.msg_type == MessageType.MSG_AUTH_SUCCESS:
            self.authenticated = True
            success_data = json.loads(result.payload.decode())
            if 'session_key' in success_data:
                self.session_key = bytes.fromhex(success_data['session_key'])
        elif result.msg_type == MessageType.MSG_AUTH_FAILURE:
            error = json.loads(result.payload).get('error', 'Permission denied')
            raise RuntimeError(f"Permission denied: {error}")
        else:
            raise RuntimeError("Unexpected response during authentication")

    # ──────────────────────────────────────────
    # Interactive session dispatcher
    # ──────────────────────────────────────────
    def start_interactive_session(self):
        if not self.authenticated:
            raise RuntimeError("Not authenticated")
        if IS_WINDOWS:
            self._session_windows()
        else:
            self._session_linux()

    # ══════════════════════════════════════════
    # Windows session
    # ──────────────────────────────────────────
    # Strategy: CLIENT-SIDE LINE BUFFERING
    #
    # cmd.exe has no PTY. The server receives characters one-by-one and
    # forwards them directly to cmd.exe stdin. Sending backspace mid-stream
    # causes cmd.exe to see "catdir" instead of "dir".
    #
    # Fix: buffer the whole line locally, send it in one shot on Enter.
    # Backspace only modifies the local buffer — nothing is sent to the server.
    # Local echo shows what you type immediately without waiting for the server.
    # The server's echo of our command is suppressed (we already showed it).
    # ══════════════════════════════════════════
    def _session_windows(self):
        console = self._win_console
        console.set_raw()

        rows, cols = console.get_console_size()
        self.send_packet(create_window_size_packet(rows, cols))

        stop        = threading.Event()
        stdout_lock = threading.Lock()
        last_sent   = ['']   # for echo suppression

        # ── Receive loop ──────────────────────────────────────────────────
        # NOTE: select.select() does NOT work reliably on Windows AF_BTH
        # (RFCOMM) sockets — it raises OSError 10038 ("not a socket") and
        # kills the session ~1 second after auth.  Use a socket timeout so
        # receive_packet() blocks-with-timeout instead of using select as a
        # readiness gate.
        self.sock.settimeout(0.2)

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

                        # Suppress the server's echo of our command (line by line)
                        cmd = last_sent[0]
                        if cmd:
                            lines = data.split('\n')
                            out_lines = []
                            suppressed = False
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
                    # Normal: no data within the 0.2 s window — keep looping.
                    continue
                except Exception as e:
                    if not stop.is_set():
                        with stdout_lock:
                            sys.stdout.write(f"\r\nReceive error: {e}\r\n")
                            sys.stdout.flush()
                    stop.set()
                    break

        t_recv = threading.Thread(target=recv_loop, daemon=True)
        t_recv.start()

        # ── Background: keepalive + window resize ─────────────────────────
        last_size = console.get_console_size()

        def background_loop():
            nonlocal last_size
            while not stop.is_set():
                # Sleep FIRST so the initial keepalive doesn't fire immediately
                # (the server would receive it before the shell loop is ready,
                # causing a spurious decrypt-on-empty-payload error).
                threading.Event().wait(0.5)
                if stop.is_set():
                    break
                try:
                    self.send_packet(BSHPacket(MessageType.MSG_KEEPALIVE))
                except Exception:
                    pass
                size = console.get_console_size()
                if size != last_size:
                    last_size = size
                    try:
                        self.send_packet(create_window_size_packet(*size))
                    except Exception:
                        pass

        t_bg = threading.Thread(target=background_loop, daemon=True)
        t_bg.start()

        # ── Local line editor ─────────────────────────────────────────────
        # Handles: typing, backspace, Del, Left, Right, Home, End,
        #          Ctrl+A/E (Home/End), history (Up/Down), Ctrl+C, Ctrl+D.
        # The complete edited line is sent to the server only on Enter.

        history     = []   # list of previously sent commands
        hist_idx    = [0]  # current position in history (0 = new input)

        def redraw_line(buf, cursor, stdout_lock, prefix_len=0):
            """Redraw the input line in place. prefix_len unused, kept for clarity."""
            with stdout_lock:
                # Move to start of input area, clear to end of line
                sys.stdout.write('\r\x1b[K')
                # Re-print everything the server sent up to our input
                # (we can't know the prompt easily, so just reprint the buffer
                #  and position the cursor correctly)
                line_str = ''.join(buf)
                sys.stdout.write(line_str)
                # Move cursor to correct position within the line
                if cursor < len(buf):
                    sys.stdout.write(f'\x1b[{len(buf) - cursor}D')
                sys.stdout.flush()

        def input_loop():
            buf      = []   # current line buffer (list of chars)
            cursor   = 0    # insertion point (index into buf)
            hist_pos = 0    # 0 = current new input, 1 = last cmd, 2 = one before...
            saved    = []   # saved buf when navigating history

            while not stop.is_set():
                try:
                    ch = msvcrt.getwch()

                    # ── Special / function key prefix ──────────────────────
                    if ch in ('\x00', '\xe0'):
                        ch2 = msvcrt.getwch()

                        # Left arrow — move cursor left
                        if ch2 == 'K':
                            if cursor > 0:
                                cursor -= 1
                                with stdout_lock:
                                    sys.stdout.write('\x1b[D')
                                    sys.stdout.flush()

                        # Right arrow — move cursor right
                        elif ch2 == 'M':
                            if cursor < len(buf):
                                cursor += 1
                                with stdout_lock:
                                    sys.stdout.write('\x1b[C')
                                    sys.stdout.flush()

                        # Home — jump to start of line
                        elif ch2 == 'G':
                            if cursor > 0:
                                with stdout_lock:
                                    sys.stdout.write(f'\x1b[{cursor}D')
                                    sys.stdout.flush()
                                cursor = 0

                        # End — jump to end of line
                        elif ch2 == 'O':
                            if cursor < len(buf):
                                with stdout_lock:
                                    sys.stdout.write(f'\x1b[{len(buf) - cursor}C')
                                    sys.stdout.flush()
                                cursor = len(buf)

                        # Delete key — delete char under cursor
                        elif ch2 == 'S':
                            if cursor < len(buf):
                                buf.pop(cursor)
                                # Reprint from cursor to end, then backspace
                                tail = ''.join(buf[cursor:]) + ' '
                                with stdout_lock:
                                    sys.stdout.write(tail)
                                    sys.stdout.write(f'\x1b[{len(tail)}D')
                                    sys.stdout.flush()

                        # Up arrow — history previous
                        elif ch2 == 'H':
                            if history and hist_pos < len(history):
                                if hist_pos == 0:
                                    saved = buf[:]   # save current draft
                                hist_pos += 1
                                buf    = list(history[-hist_pos])
                                cursor = len(buf)
                                redraw_line(buf, cursor, stdout_lock)

                        # Down arrow — history next
                        elif ch2 == 'P':
                            if hist_pos > 0:
                                hist_pos -= 1
                                if hist_pos == 0:
                                    buf = saved[:]
                                else:
                                    buf = list(history[-hist_pos])
                                cursor = len(buf)
                                redraw_line(buf, cursor, stdout_lock)

                        continue   # all special keys handled above

                    # ── Ctrl+D — disconnect ────────────────────────────────
                    if ch == '\x04':
                        self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
                        stop.set()
                        break

                    # ── Ctrl+C — interrupt ─────────────────────────────────
                    elif ch == '\x03':
                        buf.clear()
                        cursor   = 0
                        hist_pos = 0
                        with stdout_lock:
                            sys.stdout.write('^C\r\n')
                            sys.stdout.flush()
                        self.send_packet(create_data_packet('\x03\r\n', MessageType.MSG_DATA_IN))

                    # ── Ctrl+A — jump to start ─────────────────────────────
                    elif ch == '\x01':
                        if cursor > 0:
                            with stdout_lock:
                                sys.stdout.write(f'\x1b[{cursor}D')
                                sys.stdout.flush()
                            cursor = 0

                    # ── Ctrl+E — jump to end ───────────────────────────────
                    elif ch == '\x05':
                        if cursor < len(buf):
                            with stdout_lock:
                                sys.stdout.write(f'\x1b[{len(buf) - cursor}C')
                                sys.stdout.flush()
                            cursor = len(buf)

                    # ── Ctrl+K — kill to end of line ───────────────────────
                    elif ch == '\x0b':
                        if cursor < len(buf):
                            killed = len(buf) - cursor
                            buf    = buf[:cursor]
                            with stdout_lock:
                                sys.stdout.write(' ' * killed + f'\x1b[{killed}D')
                                sys.stdout.flush()

                    # ── Enter — send complete line ─────────────────────────
                    elif ch == '\r':
                        line     = ''.join(buf)
                        last_sent[0] = line
                        if line and (not history or history[-1] != line):
                            history.append(line)
                        buf      = []
                        cursor   = 0
                        hist_pos = 0
                        saved    = []
                        with stdout_lock:
                            sys.stdout.write('\r\n')
                            sys.stdout.flush()
                        self.send_packet(create_data_packet(line + '\r\n', MessageType.MSG_DATA_IN))

                    # ── Backspace — delete char before cursor ──────────────
                    elif ch in ('\x08', '\x7f'):
                        if cursor > 0:
                            buf.pop(cursor - 1)
                            cursor -= 1
                            # Erase: move back, reprint tail, blank last char, return
                            tail = ''.join(buf[cursor:]) + ' '
                            with stdout_lock:
                                sys.stdout.write('\x08' + tail + f'\x1b[{len(tail)}D')
                                sys.stdout.flush()

                    # ── Printable character — insert at cursor ─────────────
                    elif ord(ch) >= 32:
                        buf.insert(cursor, ch)
                        cursor += 1
                        # Print char + everything after it, then reposition cursor
                        tail = ''.join(buf[cursor:])
                        with stdout_lock:
                            if tail:
                                sys.stdout.write(ch + tail + f'\x1b[{len(tail)}D')
                            else:
                                sys.stdout.write(ch)
                            sys.stdout.flush()

                    # ── Other control chars — pass through ─────────────────
                    else:
                        self.send_packet(create_data_packet(ch, MessageType.MSG_DATA_IN))

                except KeyboardInterrupt:
                    buf.clear()
                    cursor = 0
                    self.send_packet(create_data_packet('\x03\r\n', MessageType.MSG_DATA_IN))
                except Exception as e:
                    if not stop.is_set():
                        with stdout_lock:
                            sys.stdout.write(f"\r\nInput error: {e}\r\n")
                            sys.stdout.flush()
                    stop.set()
                    break

        t_input = threading.Thread(target=input_loop, daemon=True)
        t_input.start()

        try:
            stop.wait()
        except KeyboardInterrupt:
            try:
                self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
            except Exception:
                pass
        finally:
            stop.set()
            # Close the socket first — this immediately unblocks recv_loop's
            # receive_packet() call so the thread exits without waiting for
            # the 0.2 s timeout to fire.  Without this, daemon threads are
            # still holding the stdout lock when the interpreter tears down,
            # causing: 'Fatal Python error: _enter_buffered_busy: could not
            # acquire lock for <_io.BufferedWriter name=stdout>'.
            try:
                self.sock.close()
                self.sock = None
            except Exception:
                pass
            # Give all daemon threads up to 1 s to notice stop and exit.
            for t in (t_recv, t_bg, t_input):
                t.join(timeout=1.0)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            console.restore()
            print(f"\r\nConnection to {self.host_addr} closed.")

    # ══════════════════════════════════════════
    # Linux session
    # ──────────────────────────────────────────
    # Strategy: CHAR-BY-CHAR (unchanged from original)
    #
    # Linux uses a real Unix PTY on the server side. The PTY kernel line
    # discipline handles echo, backspace, and line editing correctly.
    # Raw mode here means we pass every keystroke straight through.
    # ══════════════════════════════════════════
    def _session_linux(self):
        import queue

        try:
            rows, cols = os.popen('stty size', 'r').read().split()
            self.send_packet(create_window_size_packet(int(rows), int(cols)))
        except Exception:
            pass

        def handle_resize(signum, frame):
            try:
                rows, cols = os.popen('stty size', 'r').read().split()
                send_q.put(create_window_size_packet(int(rows), int(cols)))
            except Exception:
                pass

        stop        = threading.Event()
        send_q      = queue.Queue()   # Fix #2: must be defined BEFORE signal handler registration
        signal.signal(signal.SIGWINCH, handle_resize)
        stdout_fd   = sys.stdout.fileno()
        last_sent   = ['']

        def send_loop():
            while not stop.is_set():
                try:
                    packet = send_q.get(timeout=0.1)
                    self.send_packet(packet)  # use send_packet for encryption
                except queue.Empty:
                    continue
                except Exception:
                    stop.set()
                    break

        def recv_loop():
            while not stop.is_set():
                try:
                    packet = self.receive_packet()
                    if not packet:
                        os.write(stdout_fd, b"\r\nConnection closed by remote host\r\n")
                        stop.set()
                        break
                    if packet.msg_type == MessageType.MSG_DATA_OUT:
                        data = packet.payload
                        # Suppress server echo of the line we already echoed locally
                        text = data.decode('utf-8', errors='replace')
                        if last_sent[0] and last_sent[0] in text:
                            text = text.replace(last_sent[0], '', 1)
                            last_sent[0] = ''
                        if text:
                            os.write(stdout_fd, text.encode('utf-8', errors='replace'))
                    elif packet.msg_type == MessageType.MSG_DATA_ERR:
                        os.write(sys.stderr.fileno(), packet.payload)
                    elif packet.msg_type == MessageType.MSG_DISCONNECT:
                        os.write(stdout_fd, b"\r\nConnection closed by remote host\r\n")
                        stop.set()
                        break
                except socket.timeout:
                    continue  # no data yet — keep looping
                except Exception:
                    if not stop.is_set():
                        stop.set()
                    break

        t_send = threading.Thread(target=send_loop, daemon=True)
        t_recv = threading.Thread(target=recv_loop, daemon=True)
        t_send.start()
        t_recv.start()

        stdin_fd = sys.stdin.fileno()
        old_tty  = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)

        buf = []   # current line buffer

        try:
            while not stop.is_set():
                r, _, _ = select.select([stdin_fd], [], [], 0.1)
                if not r:
                    continue
                try:
                    data = os.read(stdin_fd, 32)
                except OSError:
                    break
                if not data:
                    break

                for byte in data:
                    if byte == 0x04:                         # Ctrl+D
                        send_q.put(BSHPacket(MessageType.MSG_DISCONNECT))
                        stop.set()
                        break

                    elif byte == 0x03:                       # Ctrl+C
                        buf.clear()
                        os.write(stdout_fd, b'^C\r\n')
                        send_q.put(BSHPacket(MessageType.MSG_INTERRUPT))  # ← use MSG_INTERRUPT, not MSG_DATA_IN
                    elif byte in (0x08, 0x7f):               # Backspace
                        if buf:
                            buf.pop()
                            os.write(stdout_fd, b'\x08 \x08')

                    elif byte in (0x0d, 0x0a):               # Enter
                        line = ''.join(buf)
                        last_sent[0] = line
                        buf.clear()
                        os.write(stdout_fd, b'\r\n')
                        send_q.put(create_data_packet(line + '\r\n', MessageType.MSG_DATA_IN))

                    elif byte >= 32:                          # Printable
                        buf.append(chr(byte))
                        os.write(stdout_fd, bytes([byte]))    # local echo

                    else:                                     # Other control chars
                        send_q.put(create_data_packet(chr(byte), MessageType.MSG_DATA_IN))

        finally:
            stop.set()
            # Close socket to immediately unblock recv_loop — same fix as
            # the Windows path; prevents the fatal BufferedWriter lock error
            # at interpreter shutdown when daemon threads are still running.
            try:
                self.sock.close()
                self.sock = None
            except Exception:
                pass
            for t in (t_send, t_recv):
                t.join(timeout=1.0)
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tty)
            print(f"\r\nConnection to {self.host_addr} closed.")

    # ──────────────────────────────────────────
    # Packet I/O
    # ──────────────────────────────────────────
    def send_packet(self, packet: BSHPacket):
        # Encrypt ALL packets (including empty-payload ones like MSG_KEEPALIVE)
        # once the session key is established. Skipping empty payloads was wrong:
        # the server unconditionally tries to decrypt any packet received after
        # MSG_AUTH_SUCCESS, so a plaintext empty payload causes a GCM IV-length
        # error (iv = b''[:12] = b'', which is < 8 bytes) and kills the session.
        # AES-GCM of an empty plaintext is valid: output is IV(12) + tag(16) = 28 B.
        if self.session_key:
            packet = BSHPacket(
                packet.msg_type,
                self.crypto.encrypt_data(self.session_key, packet.payload),
            )
        with self._send_lock:
            self.sock.send(packet.to_bytes())

    def receive_packet(self) -> Optional['BSHPacket']:
        header = self._recv_exact(4)
        if not header:
            return None
        length = (header[1] << 8) | header[2]
        rest   = self._recv_exact(length + 1)
        if not rest:
            return None
        packet = BSHPacket.from_bytes(header + rest)
        if packet is None:
            return None
        # Decrypt ALL packets once the session key is established.
        # Must match the send_packet policy above — type filtering here would
        # leave non-DATA packets with encrypted payloads that can't be parsed.
        if self.session_key and packet and packet.payload:
            try:
                packet = BSHPacket(
                    packet.msg_type,
                    self.crypto.decrypt_data(self.session_key, packet.payload),
                )
            except Exception:
                pass  # pass through on decryption failure (e.g. empty payload)
        return packet

    def _recv_exact(self, size: int) -> Optional[bytes]:
        data = b''
        while len(data) < size:
            try:
                chunk = self.sock.recv(size - len(data))
            except socket.timeout:
                # Re-raise so recv_loop can treat this as "no data yet"
                # rather than "connection closed".
                raise
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        return data

    def disconnect(self):
        if self.sock:
            try:
                self.send_packet(BSHPacket(MessageType.MSG_DISCONNECT))
            except Exception:
                pass
            self.sock.close()
            self.sock = None


# ══════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════
def _parse_destination(dest: str) -> Tuple[str, str]:
    if '@' in dest:
        username, mac = dest.split('@', 1)
    else:
        mac      = dest
        username = os.getenv('USERNAME' if IS_WINDOWS else 'USER', 'user')
    return username.strip(), mac.strip()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='BSH — Bluetooth Shell',
        usage='bsh [user@]<MAC> [-p port]',
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
    args = parser.parse_args()

    username, mac = _parse_destination(args.destination)

    parts = mac.split(':')
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        parser.error(f"Invalid Bluetooth address: {mac!r}  (expected XX:XX:XX:XX:XX:XX)")

    port = args.port
    if port is None:
        if IS_WINDOWS:
            port = find_bsh_channel(mac)
        else:
            port = 1

    print(f"BSH ({username}@{mac})")

    client = BSHClient(username)

    try:
        if client.connect(mac, port):
            client.start_interactive_session()
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except RuntimeError as e:
        print(f"bsh: {e}", file=sys.stderr)
        sys.exit(255)
    except Exception as e:
        print(f"bsh: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        client.disconnect()


if __name__ == '__main__':
    main()
