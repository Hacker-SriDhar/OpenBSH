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
BSH Host Service — Windows Service version with proper user impersonation.

Runs as SYSTEM (via bsh_service.py) for full CreateProcessAsUser support.
Falls back to plain subprocess when running as a regular Administrator.

Authentication supported
─────────────────────────
  • password   — Windows LogonUser credential verification
"""

import socket
import subprocess
import threading
import os
import sys
import json
import ctypes
import logging
import traceback
from datetime import datetime
from pathlib import Path
from ctypes import wintypes

from bsh_protocol import (
    BSHPacket, MessageType, BSHAuthenticator,
    create_hello_packet, create_data_packet,
)
from bsh_password import BSHPasswordAuth
from bsh_crypto import BSHCrypto

# ─────────────────────────────────────────────────────────────────────────────
# Auto-create required directories
# ─────────────────────────────────────────────────────────────────────────────
for _d in [r'C:\ProgramData\BSH', r'C:\ProgramData\BSH\logs']:
    Path(_d).mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level logger
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(r'C:\ProgramData\BSH\logs\bsh_service.log',
                            encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger('BSHServer')


# ─────────────────────────────────────────────────────────────────────────────
# Windows API structures
# ─────────────────────────────────────────────────────────────────────────────

class _GUID(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Data1',  ctypes.c_ulong),
        ('Data2',  ctypes.c_ushort),
        ('Data3',  ctypes.c_ushort),
        ('Data4',  ctypes.c_ubyte * 8),
    ]

class _SOCKADDR_BTH(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('addressFamily',  ctypes.c_ushort),
        ('btAddr',         ctypes.c_ulonglong),
        ('serviceClassId', _GUID),
        ('port',           ctypes.c_ulong),
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb',              wintypes.DWORD),
        ('lpReserved',      wintypes.LPWSTR),
        ('lpDesktop',       wintypes.LPWSTR),
        ('lpTitle',         wintypes.LPWSTR),
        ('dwX',             wintypes.DWORD),
        ('dwY',             wintypes.DWORD),
        ('dwXSize',         wintypes.DWORD),
        ('dwYSize',         wintypes.DWORD),
        ('dwXCountChars',   wintypes.DWORD),
        ('dwYCountChars',   wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags',         wintypes.DWORD),
        ('wShowWindow',     wintypes.WORD),
        ('cbReserved2',     wintypes.WORD),
        ('lpReserved2',     ctypes.POINTER(wintypes.BYTE)),
        ('hStdInput',       wintypes.HANDLE),
        ('hStdOutput',      wintypes.HANDLE),
        ('hStdError',       wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess',    wintypes.HANDLE),
        ('hThread',     wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId',  wintypes.DWORD),
    ]

class PROFILEINFO(ctypes.Structure):
    _fields_ = [
        ('dwSize',        wintypes.DWORD),
        ('dwFlags',       wintypes.DWORD),
        ('lpUserName',    wintypes.LPWSTR),
        ('lpProfilePath', wintypes.LPWSTR),
        ('lpDefaultPath', wintypes.LPWSTR),
        ('lpServerName',  wintypes.LPWSTR),
        ('lpPolicyPath',  wintypes.LPWSTR),
        ('hProfile',      wintypes.HANDLE),
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength',              wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle',       wintypes.BOOL),
    ]

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

AF_BTH                    = 32
BTHPROTO_RFCOMM           = 3
BT_PORT_ANY               = 0xFFFFFFFF

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_PROVIDER_DEFAULT  = 0

CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NO_WINDOW           = 0x08000000
STARTF_USESTDHANDLES       = 0x00000100

_SPP_GUID        = _GUID()
_SPP_GUID.Data1  = 0x00001101
_SPP_GUID.Data2  = 0x0000
_SPP_GUID.Data3  = 0x1000
_SPP_GUID.Data4  = (_SPP_GUID.Data4._type_ * 8)(
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
)

_BSH_SERVICE_UUID        = _GUID()
_BSH_SERVICE_UUID.Data1  = 0xB5E7DA7A
_BSH_SERVICE_UUID.Data2  = 0x0B53
_BSH_SERVICE_UUID.Data3  = 0x1000
_BSH_SERVICE_UUID.Data4  = (_BSH_SERVICE_UUID.Data4._type_ * 8)(
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
)

RNRSERVICE_REGISTER = 1
RNRSERVICE_DELETE   = 2
_NS_BTH             = 16

class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ('lpSockaddr',      ctypes.POINTER(_SOCKADDR_BTH)),
        ('iSockaddrLength', ctypes.c_int),
    ]

class _CSADDR_INFO(ctypes.Structure):
    _fields_ = [
        ('LocalAddr',  _SOCKET_ADDRESS),
        ('RemoteAddr', _SOCKET_ADDRESS),
        ('iSocketType', ctypes.c_int),
        ('iProtocol',   ctypes.c_int),
    ]

class _WSAQUERYSET(ctypes.Structure):
    _fields_ = [
        ('dwSize',                  wintypes.DWORD),
        ('lpszServiceInstanceName', wintypes.LPWSTR),
        ('lpServiceClassId',        ctypes.POINTER(_GUID)),
        ('lpVersion',               wintypes.LPVOID),
        ('lpszComment',             wintypes.LPWSTR),
        ('dwNameSpace',             wintypes.DWORD),
        ('lpNSProviderId',          wintypes.LPVOID),
        ('lpszContext',             wintypes.LPWSTR),
        ('dwNumberOfProtocols',     wintypes.DWORD),
        ('lpafpProtocols',          wintypes.LPVOID),
        ('lpszQueryString',         wintypes.LPWSTR),
        ('dwNumberOfCsAddrs',       wintypes.DWORD),
        ('lpcsaBuffer',             ctypes.POINTER(_CSADDR_INFO)),
        ('dwOutputFlags',           wintypes.DWORD),
        ('lpBlob',                  wintypes.LPVOID),
    ]

# ─────────────────────────────────────────────────────────────────────────────
# Utility: SYSTEM detection
# ─────────────────────────────────────────────────────────────────────────────

def _is_system() -> bool:
    try:
        import win32api, win32con
        token = win32api.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        sid   = win32api.GetTokenInformation(token, 1)
        return str(sid[0]) == 'S-1-5-18'
    except Exception:
        return os.environ.get('USERNAME', '').upper() in ('SYSTEM', '')


# ─────────────────────────────────────────────────────────────────────────────
# SDP Service Advertisement
# ─────────────────────────────────────────────────────────────────────────────

def register_sdp_service(sock: socket.socket, channel: int, service_name: str = "BSH Bluetooth Shell") -> bool:
    ws2_32 = ctypes.windll.ws2_32

    local_addr = _SOCKADDR_BTH()
    addr_len   = ctypes.c_int(ctypes.sizeof(local_addr))
    ws2_32.getsockname(sock.fileno(), ctypes.byref(local_addr), ctypes.byref(addr_len))

    addr = _SOCKADDR_BTH()
    addr.addressFamily = AF_BTH
    addr.btAddr        = local_addr.btAddr
    addr.port          = channel

    csa = _CSADDR_INFO()
    csa.LocalAddr.lpSockaddr      = ctypes.pointer(addr)
    csa.LocalAddr.iSockaddrLength = ctypes.sizeof(_SOCKADDR_BTH)
    csa.iSocketType               = socket.SOCK_STREAM
    csa.iProtocol                 = BTHPROTO_RFCOMM

    svc_name_buf = ctypes.create_unicode_buffer(service_name)
    comment_buf  = ctypes.create_unicode_buffer("BSH remote shell service")

    qs = _WSAQUERYSET()
    qs.dwSize                  = ctypes.sizeof(_WSAQUERYSET)
    qs.lpszServiceInstanceName = ctypes.cast(svc_name_buf, wintypes.LPWSTR)
    qs.lpServiceClassId        = ctypes.pointer(_SPP_GUID)
    qs.dwNameSpace             = _NS_BTH
    qs.dwNumberOfCsAddrs       = 1
    qs.lpcsaBuffer             = ctypes.pointer(csa)
    qs.lpszComment             = ctypes.cast(comment_buf, wintypes.LPWSTR)

    ret = ws2_32.WSASetServiceW(ctypes.byref(qs), RNRSERVICE_REGISTER, 0)
    if ret == 0:
        log.info("SDP: BSH service advertised (channel %d)", channel)
        return True
    else:
        err = ws2_32.WSAGetLastError()
        log.warning("SDP: WSASetService failed — WSAError %d", err)
        return False

def unregister_sdp_service() -> None:
    ws2_32 = ctypes.windll.ws2_32
    addr               = _SOCKADDR_BTH()
    addr.addressFamily = AF_BTH
    csa                           = _CSADDR_INFO()
    csa.LocalAddr.lpSockaddr      = ctypes.pointer(addr)
    csa.LocalAddr.iSockaddrLength = ctypes.sizeof(_SOCKADDR_BTH)

    svc_name_buf = ctypes.create_unicode_buffer("BSH Bluetooth Shell")
    comment_buf  = ctypes.create_unicode_buffer("BSH remote shell service")

    qs = _WSAQUERYSET()
    qs.dwSize                  = ctypes.sizeof(_WSAQUERYSET)
    qs.lpszServiceInstanceName = ctypes.cast(svc_name_buf, wintypes.LPWSTR)
    qs.lpServiceClassId        = ctypes.pointer(_SPP_GUID)
    qs.dwNameSpace             = _NS_BTH
    qs.dwNumberOfCsAddrs       = 1
    qs.lpcsaBuffer             = ctypes.pointer(csa)
    qs.lpszComment             = ctypes.cast(comment_buf, wintypes.LPWSTR)

    ws2_32.WSASetServiceW(ctypes.byref(qs), RNRSERVICE_DELETE, 0)
    log.info("SDP: service unregistered")


# ─────────────────────────────────────────────────────────────────────────────
# Shell implementations
# ─────────────────────────────────────────────────────────────────────────────

class ImpersonatedWindowsShell:
    def __init__(self, username: str, user_token: wintypes.HANDLE):
        self.username       = username
        self.user_token     = user_token
        self.process_handle = None
        self.thread_handle  = None
        self.stdin_write    = None
        self.stdout_read    = None
        self.profile_handle = None
        self.kernel32  = ctypes.windll.kernel32
        self.advapi32  = ctypes.windll.advapi32
        self.userenv   = ctypes.windll.userenv
        self._log      = logging.getLogger('BSHServer.ImpersonatedShell')

    def start(self):
        self._log.info("Starting impersonated shell for user '%s'", self.username)
        profile_info            = PROFILEINFO()
        profile_info.dwSize     = ctypes.sizeof(PROFILEINFO)
        profile_info.lpUserName = self.username
        if not self.userenv.LoadUserProfileW(self.user_token, ctypes.byref(profile_info)):
            err = self.kernel32.GetLastError()
            self._log.warning("LoadUserProfile failed for '%s' (error %d) — continuing without profile",
                              self.username, err)
        else:
            self.profile_handle = profile_info.hProfile
            self._log.debug("User profile loaded for '%s'", self.username)

        env_block = ctypes.c_void_p()
        if not self.userenv.CreateEnvironmentBlock(ctypes.byref(env_block), self.user_token, False):
            self._log.warning("CreateEnvironmentBlock failed — using default environment")
            env_block = None
        else:
            self._log.debug("User environment block created")

        sa            = SECURITY_ATTRIBUTES()
        sa.nLength    = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.bInheritHandle = True

        stdin_read  = wintypes.HANDLE()
        stdin_write = wintypes.HANDLE()
        self.kernel32.CreatePipe(ctypes.byref(stdin_read), ctypes.byref(stdin_write), ctypes.byref(sa), 0)
        self.kernel32.SetHandleInformation(stdin_write, 1, 0)

        stdout_read  = wintypes.HANDLE()
        stdout_write = wintypes.HANDLE()
        self.kernel32.CreatePipe(ctypes.byref(stdout_read), ctypes.byref(stdout_write), ctypes.byref(sa), 0)
        self.kernel32.SetHandleInformation(stdout_read, 1, 0)
        self._log.debug("I/O pipes created")

        si            = STARTUPINFO()
        si.cb         = ctypes.sizeof(STARTUPINFO)
        si.dwFlags    = STARTF_USESTDHANDLES
        si.hStdInput  = stdin_read
        si.hStdOutput = stdout_write
        si.hStdError  = stdout_write
        si.lpDesktop  = "winsta0\\default"

        profile_dir = f"C:\\Users\\{self.username}"
        if not Path(profile_dir).exists():
            profile_dir = "C:\\Windows\\System32"
        self._log.debug("Working directory: %s", profile_dir)

        pi      = PROCESS_INFORMATION()
        cmdline = ctypes.create_unicode_buffer("cmd.exe")

        self._log.debug("Calling CreateProcessAsUserW for '%s'", self.username)
        result = self.advapi32.CreateProcessAsUserW(
            self.user_token, None, cmdline, None, None, True,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            env_block, profile_dir, ctypes.byref(si), ctypes.byref(pi),
        )

        if env_block:
            self.userenv.DestroyEnvironmentBlock(env_block)

        if not result:
            err = self.kernel32.GetLastError()
            for h in (stdin_read, stdin_write, stdout_read, stdout_write):
                self.kernel32.CloseHandle(h)
            self._log.error("CreateProcessAsUser failed: error %d", err)
            raise OSError(f"CreateProcessAsUser failed: error {err}")

        self.kernel32.CloseHandle(stdin_read)
        self.kernel32.CloseHandle(stdout_write)
        self.process_handle = pi.hProcess
        self.thread_handle  = pi.hThread
        self.stdin_write    = stdin_write
        self.stdout_read    = stdout_read
        self._log.info("Impersonated shell started as '%s' (PID %d)",
                       self.username, pi.dwProcessId)
        return True

    def write(self, data: bytes):
        try:
            n = wintypes.DWORD()
            self.kernel32.WriteFile(self.stdin_write, data, len(data), ctypes.byref(n), None)
        except Exception as exc:
            self._log.warning("Shell stdin write error: %s", exc)

    def read(self, size: int = 4096) -> bytes:
        try:
            buf = ctypes.create_string_buffer(size)
            n   = wintypes.DWORD()
            ok  = self.kernel32.ReadFile(self.stdout_read, buf, size, ctypes.byref(n), None)
            result = buf.raw[:n.value] if ok else b''
            return result
        except Exception as exc:
            self._log.debug("Shell stdout read error: %s", exc)
            return b''

    def is_running(self) -> bool:
        if not self.process_handle:
            return False
        code = wintypes.DWORD()
        self.kernel32.GetExitCodeProcess(self.process_handle, ctypes.byref(code))
        return code.value == 259

    def send_ctrl_c(self):
        self._log.info("Sending Ctrl+C to shell")
        try:
            # Write ^C to cmd.exe stdin pipe
            data = b'\x03'
            n = wintypes.DWORD()
            self.kernel32.WriteFile(self.stdin_write, data, len(data), ctypes.byref(n), None)
        except Exception as exc:
            self._log.warning("send_ctrl_c error: %s", exc)

    def stop(self):
        self._log.info("Stopping impersonated shell for '%s'", self.username)
        # Bug #5 fix: null each handle after closing to prevent double-close crashes
        if self.process_handle:
            self.kernel32.TerminateProcess(self.process_handle, 0)
            self.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None
        if self.thread_handle:
            self.kernel32.CloseHandle(self.thread_handle)
            self.thread_handle = None
        if self.stdin_write:
            self.kernel32.CloseHandle(self.stdin_write)
            self.stdin_write = None
        if self.stdout_read:
            self.kernel32.CloseHandle(self.stdout_read)
            self.stdout_read = None
        if self.profile_handle and self.user_token:
            self.userenv.UnloadUserProfileW(self.user_token, self.profile_handle)
            self.profile_handle = None


class PlainWindowsShell:
    def __init__(self, username: str):
        self.username   = username
        self.proc       = None
        self._stdin_fd  = None
        self._stdout_fd = None
        self._log       = logging.getLogger('BSHServer.PlainShell')

    def start(self):
        shell    = os.environ.get('COMSPEC', 'cmd.exe')
        home_dir = Path(f"C:\\Users\\{self.username}")
        cwd      = str(home_dir) if home_dir.exists() else os.environ.get('USERPROFILE', 'C:\\')

        self._log.info("Starting plain shell for '%s' (cwd: %s)", self.username, cwd)
        self.proc = subprocess.Popen(
            [shell],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=-1,
            cwd=cwd,
        )
        self._stdin_fd  = self.proc.stdin.fileno()
        self._stdout_fd = self.proc.stdout.fileno()
        self._log.info("Plain shell started for '%s' (PID %d)", self.username, self.proc.pid)
        return True

    def write(self, data: bytes):
        try:
            os.write(self._stdin_fd, data)
        except OSError as exc:
            self._log.warning("Shell stdin write error: %s", exc)

    def read(self, size: int = 4096) -> bytes:
        try:
            return os.read(self._stdout_fd, size)
        except OSError as exc:
            self._log.debug("Shell stdout read error: %s", exc)
            return b''

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def send_ctrl_c(self):
        self._log.info("Sending Ctrl+C to shell")
        try:
            # Write ^C directly to cmd.exe stdin — safest approach
            # CTRL_C_EVENT kills the whole process group including the server
            os.write(self._stdin_fd, b'\x03')
        except OSError as exc:
            self._log.warning("send_ctrl_c write error: %s", exc)

    def stop(self):
        self._log.info("Stopping plain shell for '%s'", self.username)
        if self.proc:
            try:
                self.proc.terminate()
            except Exception as exc:
                self._log.warning("Error terminating shell: %s", exc)


def make_shell(username: str, user_token) -> object:
    if user_token and _is_system():
        log.info("Running as SYSTEM — using ImpersonatedWindowsShell for '%s'", username)
        return ImpersonatedWindowsShell(username, user_token)
    log.info("Not SYSTEM — using PlainWindowsShell for '%s'", username)
    return PlainWindowsShell(username)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Authentication
# ─────────────────────────────────────────────────────────────────────────────

class WindowsAuthService:
    def __init__(self):
        self.advapi32 = ctypes.windll.advapi32
        self._log     = logging.getLogger('BSHServer.WinAuth')

    def verify_password(self, username: str, password: str):
        if not password:
            self._log.warning("verify_password: empty password rejected for '%s'", username)
            return None
        self._log.debug("Calling LogonUser for Windows user '%s'", username)
        token  = wintypes.HANDLE()
        result = self.advapi32.LogonUserW(
            username, None, password,
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
            ctypes.byref(token),
        )
        if result:
            self._log.info("LogonUser succeeded for '%s'", username)
            return token
        else:
            err = ctypes.windll.kernel32.GetLastError()
            self._log.warning("LogonUser FAILED for '%s' (error %d)", username, err)
            return None

    def user_exists(self, username: str) -> bool:
        try:
            r = subprocess.run(['net', 'user', username], capture_output=True, text=True)
            return r.returncode == 0
        except Exception as exc:
            self._log.warning("user_exists check failed for '%s': %s", username, exc)
            return False


# ─────────────────────────────────────────────────────────────────────────────
# BSH Host Service
# ─────────────────────────────────────────────────────────────────────────────

class BSHHostService:
    def __init__(
        self,
        password_file: str = None,
        channel: int = 1,
    ):
        self._log      = logging.getLogger('BSHServer.HostService')
        self.win_auth  = WindowsAuthService()
        self.crypto    = BSHCrypto()          # Bug #1 fix: crypto engine

        default_pw            = r'C:\ProgramData\BSH\passwords'
        self.password_file    = password_file or default_pw
        self.password_auth: BSHPasswordAuth = None

        self.server_sock        = None
        self.client_sock        = None
        self._client_addr       = None
        self.running            = False
        self.authenticated_user = None
        self.user_token         = None
        self.session_key: bytes = None        # Bug #1 fix: active AES-256-GCM key
        self._encrypted         = False       # Bug #1 fix: encryption active flag
        self._send_lock         = threading.Lock()
        self._connection_count  = 0
        self.bound_channel      = None
        self._runtime_file      = Path(r'C:\ProgramData\BSH\runtime.json')

        self._load_password_db()

    def _load_password_db(self):
        try:
            self.password_auth = BSHPasswordAuth(self.password_file)
            n = len(self.password_auth.users)
            if n:
                self._log.info("Loaded %d password user(s) from %s", n, self.password_file)
            else:
                self._log.info("Password DB loaded but empty: %s", self.password_file)
        except Exception as exc:
            self._log.warning("Could not load password DB (%s): %s", self.password_file, exc)
            self.password_auth = None

    def _create_rfcomm_socket(self) -> socket.socket:
        sock = socket.socket(AF_BTH, socket.SOCK_STREAM, BTHPROTO_RFCOMM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    def _win_bind_rfcomm(self, sock: socket.socket, channel: int) -> int:
        ws2_32 = ctypes.windll.ws2_32
        fileno = sock.fileno()

        addr = _SOCKADDR_BTH()
        addr.addressFamily  = AF_BTH
        addr.btAddr         = 0
        addr.serviceClassId = _SPP_GUID
        # Bug #3 fix: use the requested channel when valid; fall back to BT_PORT_ANY only when 0
        addr.port           = channel if channel > 0 else BT_PORT_ANY

        ret = ws2_32.bind(fileno, ctypes.byref(addr), ctypes.sizeof(addr))
        if ret != 0:
            err = ws2_32.WSAGetLastError()
            self._log.error("Winsock bind failed: WSAError %d", err)
            raise OSError(f"Winsock bind failed: WSAError {err}")

        out     = _SOCKADDR_BTH()
        out_len = ctypes.c_int(ctypes.sizeof(out))
        ws2_32.getsockname(fileno, ctypes.byref(out), ctypes.byref(out_len))
        assigned = int(out.port)
        self._log.info("RFCOMM socket bound to channel %d", assigned)
        return assigned

    def start_server(self, channel: int = 1):
        self._log.info("=" * 60)
        self._log.info("BSH Host Service starting")
        self._log.info("Running as : %s", os.environ.get('USERNAME', 'SYSTEM'))
        self._log.info("Requested channel : %d", channel)
        self._log.info("Auth modes : password")

        self.server_sock  = self._create_rfcomm_socket()
        requested_channel = channel
        channel           = self._win_bind_rfcomm(self.server_sock, channel)
        self.bound_channel = channel
        self.server_sock.listen(1)
        self.server_sock.settimeout(1.0)

        if channel != requested_channel:
            self._log.warning(
                "Requested channel %d but OS assigned channel %d.",
                requested_channel, channel
            )
        self._log.info("Listening on RFCOMM channel %d (backlog=1)", channel)

        register_sdp_service(self.server_sock, channel)

        mode = "SYSTEM (full impersonation)" if _is_system() else "Admin (plain subprocess)"
        self._log.info("Shell mode : %s", mode)
        self._log.info("=" * 60)
        self._log.info("Ready — waiting for Bluetooth connections …")

        self._write_runtime_state(channel)

        self.running = True
        while self.running:
            try:
                client_sock, client_addr = self.server_sock.accept()
                client_sock.settimeout(None)
                self._connection_count += 1
                conn_id = self._connection_count
                self._log.info("[conn#%d] CONNECT from %s", conn_id, client_addr)
                self.client_sock  = client_sock
                self._client_addr = client_addr
                self.handle_client(conn_id)
            except KeyboardInterrupt:
                self._log.info("Ctrl+C received — shutting down")
                self.running = False
                unregister_sdp_service()
                break
            except socket.timeout:
                continue
            except Exception as exc:
                if self.running:
                    self._log.error("Server accept error: %s", exc, exc_info=True)
                break

        self._log.info("Server loop exited")

    def handle_client(self, conn_id: int = 0):
        addr = self._client_addr
        try:
            self._log.info("[conn#%d] Starting handshake with %s", conn_id, addr)

            hello_pkt = create_hello_packet({
                'name':     'BSH-Host-Service',
                'version':  '1.0',
                'os':       'Windows',
                'features': ['pty', 'signals', 'password'],
            })
            self.send_packet(hello_pkt)
            self._log.info("[conn#%d] MSG_HELLO sent", conn_id)

            client_hello = self.receive_packet()
            if not client_hello or client_hello.msg_type != MessageType.MSG_HELLO:
                self._log.warning("[conn#%d] Invalid handshake. Closing.", conn_id)
                self._send_failure('Expected MSG_HELLO')
                return

            self._log.info("[conn#%d] Client MSG_HELLO received from %s", conn_id, addr)

            try:
                hello_data  = json.loads(client_hello.payload.decode('utf-8'))
            except Exception as exc:
                self._send_failure('Malformed MSG_HELLO payload')
                return

            username    = hello_data.get('username', '').strip()
            auth_method = hello_data.get('auth_method', 'password')
            client_name = hello_data.get('name', 'unknown')

            self._log.info(
                "[conn#%d] Client='%s'  user='%s'  auth='%s'",
                conn_id, client_name, username, auth_method
            )

            if not username:
                self._send_failure('No username specified')
                return

            if auth_method != 'password':
                self._log.warning("[conn#%d] Unsupported auth method '%s'", conn_id, auth_method)
                self._send_failure(f"Unsupported auth method: {auth_method!r}. Only password auth is allowed.")
                return

            self._log.info("[conn#%d] Starting password auth for '%s'", conn_id, username)
            token = self.authenticate_password(username, conn_id)
            if not token:
                self._log.warning("[conn#%d] Password auth FAILED for '%s'", conn_id, username)
                return
            
            self.user_token = token
            self.authenticated_user = username
            self._log.info("[conn#%d] AUTH SUCCESS — user='%s' — starting shell session", conn_id, username)
            self.start_shell_session(conn_id)

        except Exception as exc:
            self._log.error(
                "[conn#%d] Unhandled exception: %s\n%s",
                conn_id, exc, traceback.format_exc()
            )
        finally:
            self._log.info("[conn#%d] DISCONNECT", conn_id)
            if self.client_sock:
                try:
                    self.client_sock.close()
                except Exception:
                    pass
                self.client_sock = None
            if self.user_token:
                try:
                    val = getattr(self.user_token, 'value', None)
                    if val is not None and val not in (-1, 0):
                        ctypes.windll.kernel32.CloseHandle(self.user_token)
                except Exception:
                    pass
            self.user_token         = None
            self.authenticated_user = None
            self._client_addr       = None
            self.session_key        = None   # Bug #1 fix: clear session key on disconnect
            self._encrypted         = False  # Bug #1 fix: reset encryption flag

    def authenticate_password(self, username: str, conn_id: int = 0):
        pkt = self.receive_packet()
        if not pkt or pkt.msg_type != MessageType.MSG_AUTH_PASSWORD_REQUEST:
            self._send_failure('Expected MSG_AUTH_PASSWORD_REQUEST')
            return None

        challenge = os.urandom(32)
        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_PASSWORD_CHALLENGE,
            json.dumps({'challenge': challenge.hex()}).encode('utf-8'),
        ))

        resp = self.receive_packet()
        if not resp or resp.msg_type != MessageType.MSG_AUTH_PASSWORD_RESPONSE:
            self._send_failure('Expected MSG_AUTH_PASSWORD_RESPONSE')
            return None

        try:
            resp_data = json.loads(resp.payload.decode('utf-8'))
        except Exception:
            self._send_failure('Malformed password response')
            return None

        password = resp_data.get('password', '')

        if self.password_auth and username in self.password_auth.users:
            proof = resp_data.get('proof')
            if proof is not None:
                if not self.password_auth.verify_password_proof(username, challenge, proof):
                    self._send_failure('Authentication failed')
                    return None
                sys_user = self.password_auth.get_system_user(username)
            else:
                if not self.password_auth.verify_password(username, password):
                    self._send_failure('Authentication failed')
                    return None
                sys_user = self.password_auth.get_system_user(username)
        else:
            sys_user = username

        if not self.win_auth.user_exists(sys_user):
            self._send_failure('User not found on this system')
            return None

        token = self.win_auth.verify_password(sys_user, password)
        if not token:
            self._send_failure('Windows authentication failed')
            return None

        # Bug #1 fix: generate session key now so it is included in MSG_AUTH_SUCCESS
        self.session_key = self.crypto.generate_session_key()

        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_SUCCESS,
            json.dumps({
                'status':      'authenticated',
                'username':    username,
                # Bug #1 fix: include session key so client can set up encryption
                'session_key': self.session_key.hex(),
            }).encode('utf-8'),
        ))
        # Bug #1 fix: activate payload encryption for all subsequent packets
        self._encrypted = True
        return token

    def start_shell_session(self, conn_id: int = 0):
        # Bug #2 fix: apply a short socket timeout so the loop can re-check
        # shell.is_running() without blocking forever inside recv().
        self.client_sock.settimeout(0.5)
        real_token = (
            self.user_token
            if self.user_token and getattr(self.user_token, 'value', -1) not in (None, -1, 0)
            else None
        )
        username = self.authenticated_user
        shell = make_shell(username, real_token)

        try:
            shell.start()
        except Exception as exc:
            self._send_failure(f'Failed to start shell: {exc}')
            return

        welcome = f"Welcome to BSH — {username}@{socket.gethostname()}\r\n"
        self.send_packet(create_data_packet(welcome, MessageType.MSG_DATA_OUT))

        def _shell_to_client():
            while shell.is_running():
                try:
                    data = shell.read(4096)
                    if data:
                        self.send_packet(
                            create_data_packet(
                                data.decode('utf-8', errors='replace'),
                                MessageType.MSG_DATA_OUT,
                            )
                        )
                except Exception:
                    break

        threading.Thread(target=_shell_to_client, daemon=True).start()

        while shell.is_running():
            try:
                packet = self.receive_packet()
                if not packet:
                    break
                mt = packet.msg_type
                if mt == MessageType.MSG_DATA_IN:
                    shell.write(packet.payload)
                elif mt == MessageType.MSG_INTERRUPT:
                    shell.send_ctrl_c()
                elif mt == MessageType.MSG_KEEPALIVE:
                    self.send_packet(BSHPacket(MessageType.MSG_KEEPALIVE))
                elif mt in (MessageType.MSG_WINDOW_SIZE, MessageType.MSG_WINDOW_RESIZE):
                    pass   # cmd.exe has no PTY; size packets accepted but not applied
                elif mt == MessageType.MSG_DISCONNECT:
                    break
            except socket.timeout:
                # Bug #2 fix: timeout lets the loop re-evaluate shell.is_running()
                continue
            except Exception:
                break

        shell.stop()

    def _send_failure(self, msg: str):
        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_FAILURE,
            json.dumps({'error': msg}).encode('utf-8'),
        ))

    def send_packet(self, packet: BSHPacket):
        # Bug #1 fix: encrypt the payload with AES-256-GCM after authentication
        if self._encrypted and self.session_key:
            encrypted_payload = self.crypto.encrypt_data(self.session_key, packet.payload)
            packet = BSHPacket(packet.msg_type, encrypted_payload)
        raw = packet.to_bytes()
        with self._send_lock:
            self.client_sock.sendall(raw)

    def receive_packet(self) -> BSHPacket:
        header = self._recv_exact(4)
        if not header:
            return None

        if header[0] != BSHPacket.SOF:
            return None

        length   = (header[1] << 8) | header[2]
        rest = self._recv_exact(length + 1)
        if not rest:
            return None

        pkt = BSHPacket.from_bytes(header + rest)
        # Bug #1 fix: decrypt the payload with AES-256-GCM after authentication
        if pkt and self._encrypted and self.session_key:
            try:
                decrypted_payload = self.crypto.decrypt_data(self.session_key, pkt.payload)
                pkt = BSHPacket(pkt.msg_type, decrypted_payload)
            except Exception as exc:
                self._log.warning("Decryption failed: %s", exc)
                return None
        return pkt

    def _recv_exact(self, size: int) -> bytes:
        """Read exactly *size* bytes from the client socket.

        socket.timeout is re-raised so start_shell_session's
        'except socket.timeout: continue' clause handles it rather than
        treating a timeout as a disconnect.  All other I/O errors return None.
        """
        data = b''
        while len(data) < size:
            try:
                chunk = self.client_sock.recv(size - len(data))
            except socket.timeout:
                raise   # propagate so outer loop continues instead of breaking
            except Exception:
                return None
            if not chunk:
                return None
            data += chunk
        return data

    def _write_runtime_state(self, channel: int) -> None:
        state = {
            'bound_channel': channel,
            'pid':           os.getpid(),
            'started_at':    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        try:
            self._runtime_file.parent.mkdir(parents=True, exist_ok=True)
            self._runtime_file.write_text(
                json.dumps(state, indent=2), encoding='utf-8'
            )
        except Exception as exc:
            self._log.warning('Could not write runtime state file: %s', exc)

    def _clear_runtime_state(self) -> None:
        try:
            if self._runtime_file.exists():
                self._runtime_file.unlink()
        except Exception:
            pass

    def stop(self):
        self.running = False
        unregister_sdp_service()
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        self._clear_runtime_state()

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        log.error("Administrator privileges required. Run as Administrator.")
        return 1

    host = BSHHostService()
    try:
        host.start_server(channel=0)
    except KeyboardInterrupt:
        host.stop()
    return 0

if __name__ == '__main__':
    sys.exit(main())