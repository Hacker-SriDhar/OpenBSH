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
BSH Host Service — Linux version with PTY shell and user impersonation.

Authentication supported
─────────────────────────
  • BSH password DB — PBKDF2-HMAC-SHA256 with HMAC challenge-response
  • PAM               — system authentication for non-BSH-DB users
                        (requires python-pam:  pip install python-pam)

Shell
─────
  • Uses Linux PTY (pty.openpty + fork), giving clients a proper terminal.
  • When running as root the shell is launched as the authenticated user via
    os.setuid() / os.setgid() — identical to how sshd works.
  • When running as non-root the shell runs as the current OS user.

SDP advertisement
─────────────────
  • Uses PyBluez (bluetooth.advertise_service) when available.
  • Falls back gracefully if PyBluez is not installed — the service still
    works; clients must connect directly by channel number.
"""

import socket
import subprocess
import threading
import os
import sys
import pty
import fcntl
import select
import signal
import pwd
import grp
import json
import logging
import traceback
from datetime import datetime
from pathlib import Path

from bsh_protocol import (
    BSHPacket, MessageType, BSHAuthenticator,
    create_hello_packet, create_data_packet,
)
from bsh_password import BSHPasswordAuth
from bsh_crypto import BSHCrypto


# ─────────────────────────────────────────────────────────────────────────────
# Linux path constants  (mirrors C:\ProgramData\BSH on Windows)
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR         = Path('/var/lib/bsh')
LOG_DIR          = Path('/var/log/bsh')
RUN_DIR          = Path('/run/bsh')
DEFAULT_PW_FILE  = '/var/lib/bsh/passwords'
RUNTIME_JSON     = RUN_DIR / 'runtime.json'
LOG_FILE         = LOG_DIR / 'bsh_service.log'

# Create directories on import (best-effort — bsh_service.py also does this)
for _d in [BASE_DIR, LOG_DIR]:
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Module-level logger
# ─────────────────────────────────────────────────────────────────────────────

_handlers = [logging.StreamHandler(sys.stdout)]
try:
    _handlers.insert(0, logging.FileHandler(str(LOG_FILE), encoding='utf-8'))
except (PermissionError, OSError):
    pass  # running without write access to /var/log/bsh

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
    handlers=_handlers,
)
log = logging.getLogger('BSHServer')


# ─────────────────────────────────────────────────────────────────────────────
# Bluetooth constants (Python 3 built-in)
# ─────────────────────────────────────────────────────────────────────────────

AF_BLUETOOTH  = socket.AF_BLUETOOTH
BTPROTO_RFCOMM = socket.BTPROTO_RFCOMM


# ─────────────────────────────────────────────────────────────────────────────
# SDP Service Advertisement via PyBluez (optional)
# ─────────────────────────────────────────────────────────────────────────────

try:
    import bluetooth as _pybluez          # pip install PyBluez
    _HAS_PYBLUEZ = True
except ImportError:
    _pybluez = None
    _HAS_PYBLUEZ = False


BSH_SERVICE_UUID = "B5E7DA7A-0B53-1000-8000-00805F9B34FB"


def _sdptool_add_service(channel: int, service_name: str) -> bool:
    """
    Fallback SDP registration using the sdptool command-line utility.

    Required when bluetoothd is running WITHOUT the --compat flag (BlueZ 5+
    default), which blocks PyBluez's socket-based SDP writes.

    To enable PyBluez native SDP instead, add --compat to bluetoothd:
        sudo mkdir -p /etc/systemd/system/bluetooth.service.d
        echo '[Service]\nExecStart=\nExecStart=/usr/libexec/bluetooth/bluetoothd --compat' \\
            | sudo tee /etc/systemd/system/bluetooth.service.d/compat.conf
        sudo systemctl daemon-reload && sudo systemctl restart bluetooth
    """
    try:
        result = subprocess.run(
            ['sdptool', 'add', '--channel', str(channel), 'SP'],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            log.info(
                "SDP: sdptool registered Serial Port on channel %d", channel,
            )
            return True
        log.warning(
            "SDP: sdptool failed (rc=%d): %s",
            result.returncode, result.stderr.strip() or result.stdout.strip(),
        )
    except FileNotFoundError:
        log.warning("SDP: sdptool not found — install with: sudo apt install bluez")
    except Exception as exc:
        log.warning("SDP: sdptool error: %s", exc)
    return False


def register_sdp_service(
    sock: socket.socket,
    channel: int,
    service_name: str = "BSH Bluetooth Shell",
) -> bool:
    """
    Advertise the BSH service in the BlueZ SDP database.

    Tries PyBluez advertise_service first; falls back to sdptool if that
    fails with a 'no advertisable device' error (bluetoothd without --compat).
    If both fail, logs a warning — clients can still connect by explicit channel.
    """
    if _HAS_PYBLUEZ:
        try:
            _pybluez.advertise_service(
                sock,
                service_name,
                service_id=BSH_SERVICE_UUID,
                service_classes=[_pybluez.SERIAL_PORT_CLASS],
                profiles=[_pybluez.SERIAL_PORT_PROFILE],
            )
            log.info(
                "SDP: BSH service advertised on channel %d (UUID %s)",
                channel, BSH_SERVICE_UUID,
            )
            return True
        except Exception as exc:
            log.debug("SDP: PyBluez advertise_service failed (%s), trying sdptool", exc)

    # PyBluez unavailable or failed — try sdptool
    if _sdptool_add_service(channel, service_name):
        return True

    log.warning(
        "BSHServer: SDP advertisement failed: no advertisable device "
        "— clients must use explicit channel\n"
        "  Hint: enable compat mode so SDP works:\n"
        "    sudo mkdir -p /etc/systemd/system/bluetooth.service.d\n"
        "    printf '[Service]\\nExecStart=\\nExecStart=/usr/libexec/bluetooth/bluetoothd --compat\\n' "
        "| sudo tee /etc/systemd/system/bluetooth.service.d/compat.conf\n"
        "    sudo systemctl daemon-reload && sudo systemctl restart bluetooth"
    )
    return False


def unregister_sdp_service(sock: socket.socket = None) -> None:
    """Remove the BSH service from the BlueZ SDP database."""
    if not _HAS_PYBLUEZ or sock is None:
        return
    try:
        _pybluez.stop_advertising(sock)
        log.info("SDP: service unregistered")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _is_root() -> bool:
    """Return True when the process is running as UID 0 (root)."""
    return os.geteuid() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Linux PTY Shell  (replaces ImpersonatedWindowsShell + PlainWindowsShell)
# ─────────────────────────────────────────────────────────────────────────────

class LinuxPTYShell:
    """
    PTY-based shell with optional user impersonation.

    • Root process: forks a child that drops to uid/gid of *username*
      then exec's the user's login shell — identical to how sshd works.
    • Non-root: forks a child that exec's /bin/bash as the current user.

    The master PTY fd is exposed for non-blocking read/write by the server.
    """

    def __init__(self, username: str):
        self.username   = username
        self._master_fd: int | None = None
        self._child_pid: int | None = None
        self._log       = logging.getLogger('BSHServer.LinuxShell')

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Fork a PTY child shell. Returns True on success."""
        # Resolve user info (raises ValueError if user does not exist)
        try:
            pw = pwd.getpwnam(self.username)
        except KeyError:
            raise ValueError(f"System user '{self.username}' not found")

        uid   = pw.pw_uid
        gid   = pw.pw_gid
        home  = pw.pw_dir or f"/home/{self.username}"
        shell = pw.pw_shell or '/bin/bash'

        # Build supplementary group list
        supp_groups = [g.gr_gid for g in grp.getgrall() if self.username in g.gr_mem]

        master_fd, slave_fd = pty.openpty()

        pid = os.fork()

        if pid == 0:    # ── child ─────────────────────────────────────────
            try:
                os.close(master_fd)

                # Set the slave PTY as the process's controlling terminal
                os.setsid()
                fcntl.ioctl(slave_fd, _TIOCSCTTY(), 0)

                # Wire stdin/stdout/stderr → slave PTY
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                if slave_fd > 2:
                    os.close(slave_fd)

                # Drop privileges when we are root
                if _is_root():
                    if supp_groups:
                        os.setgroups(supp_groups)
                    os.setgid(gid)
                    os.setuid(uid)

                # Switch to the user's home directory
                try:
                    os.chdir(home if Path(home).exists() else '/')
                except OSError:
                    os.chdir('/')

                # Build a clean login environment
                env = {
                    'HOME':    home,
                    'USER':    self.username,
                    'LOGNAME': self.username,
                    'SHELL':   shell,
                    'TERM':    'xterm-256color',
                    'LANG':    os.environ.get('LANG', 'en_US.UTF-8'),
                    'LC_ALL':  os.environ.get('LC_ALL', ''),
                    'PATH':    '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                }
                env = {k: v for k, v in env.items() if v}  # drop empty values

                # Exec as a login shell (leading '-' signals login shell to bash/sh)
                login_argv0 = '-' + os.path.basename(shell)
                os.execve(shell, [login_argv0], env)
            except Exception:
                os._exit(1)

        # ── parent ────────────────────────────────────────────────────────────
        os.close(slave_fd)
        self._master_fd = master_fd
        self._child_pid = pid
        self._log.info(
            "PTY shell started for '%s' (child PID %d, shell=%s)",
            self.username, pid, shell,
        )
        return True

    # ── I/O ───────────────────────────────────────────────────────────────────

    def write(self, data: bytes) -> None:
        """Write *data* to the shell's stdin (master PTY)."""
        try:
            os.write(self._master_fd, data)
        except OSError as exc:
            self._log.warning("Shell stdin write error: %s", exc)

    def read(self, size: int = 4096) -> bytes:
        """Non-blocking read from the shell's stdout (master PTY)."""
        try:
            r, _, _ = select.select([self._master_fd], [], [], 0.05)
            if r:
                return os.read(self._master_fd, size)
            return b''
        except (OSError, select.error):
            return b''

    # ── State ─────────────────────────────────────────────────────────────────

    def is_running(self) -> bool:
        """Return True while the child process is still alive."""
        if self._child_pid is None:
            return False
        try:
            pid, _ = os.waitpid(self._child_pid, os.WNOHANG)
            if pid == 0:
                return True          # still running
            self._child_pid = None   # process has exited, reap it
            return False
        except ChildProcessError:
            self._child_pid = None
            return False

    # ── Signals ───────────────────────────────────────────────────────────────

    def send_ctrl_c(self) -> None:
        """Send SIGINT to the child shell (equivalent to Ctrl+C)."""
        self._log.info("Sending SIGINT to child PID %s", self._child_pid)
        if self._child_pid:
            try:
                os.kill(self._child_pid, signal.SIGINT)
            except OSError as exc:
                self._log.warning("send_ctrl_c error: %s", exc)

    def resize_pty(self, rows: int, cols: int) -> None:
        """Resize the pseudo-terminal to *rows* × *cols*."""
        if self._master_fd is None:
            return
        import struct, termios
        ws = struct.pack('HHHH', rows, cols, 0, 0)
        try:
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, ws)
        except OSError:
            pass

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def stop(self) -> None:
        """Kill the child shell and close the master PTY fd."""
        self._log.info("Stopping shell for '%s'", self.username)
        if self._child_pid:
            try:
                os.kill(self._child_pid, signal.SIGTERM)
                os.waitpid(self._child_pid, 0)
            except OSError:
                pass
            self._child_pid = None
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None


def _TIOCSCTTY():
    """Return the TIOCSCTTY ioctl number for the current platform."""
    import termios
    return termios.TIOCSCTTY


def make_shell(username: str) -> LinuxPTYShell:
    """Factory — always returns a LinuxPTYShell."""
    if _is_root():
        log.info("Running as root — spawning impersonated shell for '%s'", username)
    else:
        log.info("Not root — shell runs as current user (target: '%s')", username)
    return LinuxPTYShell(username)


# ─────────────────────────────────────────────────────────────────────────────
# Linux Authentication  (replaces WindowsAuthService)
# ─────────────────────────────────────────────────────────────────────────────

class LinuxAuthService:
    """
    Authenticates OS users via PAM or /etc/shadow.

    PAM is preferred (python-pam pip package).  Shadow fallback is used when
    PAM is unavailable — requires the process to run as root to read
    /etc/shadow.
    """

    def __init__(self):
        self._log = logging.getLogger('BSHServer.LinuxAuth')
        self._pam = None
        self._has_pam = False

        try:
            import pam as _pam_mod        # pip install python-pam
            self._pam = _pam_mod.pam()
            self._has_pam = True
            self._log.info("PAM authentication available")
        except ImportError:
            self._log.warning(
                "python-pam not available — will use /etc/shadow fallback.  "
                "Install with:  pip install python-pam"
            )

    def verify_password(self, username: str, password: str) -> bool:
        """
        Verify *username* / *password* via PAM or shadow.

        Returns True on success, False on failure.
        """
        if not password:
            self._log.warning("verify_password: empty password rejected for '%s'", username)
            return False

        if self._has_pam:
            result = self._pam.authenticate(username, password, service='login')
            if result:
                self._log.info("PAM auth succeeded for '%s'", username)
            else:
                self._log.warning(
                    "PAM auth FAILED for '%s': %s",
                    username, getattr(self._pam, 'reason', 'unknown'),
                )
            return result

        return self._verify_shadow(username, password)

    def _verify_shadow(self, username: str, password: str) -> bool:
        """Fallback authenticator using /etc/shadow + crypt."""
        import hmac as _hmac
        try:
            import spwd
            entry  = spwd.getspnam(username)
            stored = entry.sp_pwdp
        except ImportError:
            self._log.error("spwd module not available (Python ≥ 3.13 removed it)")
            return False
        except KeyError:
            self._log.warning("Shadow entry not found for '%s'", username)
            return False
        except PermissionError:
            self._log.error(
                "Cannot read /etc/shadow — start bsh_service as root or install python-pam"
            )
            return False

        try:
            import crypt
            computed = crypt.crypt(password, stored)
            result   = _hmac.compare_digest(computed, stored)
            if result:
                self._log.info("Shadow auth succeeded for '%s'", username)
            else:
                self._log.warning("Shadow auth FAILED for '%s'", username)
            return result
        except Exception as exc:
            self._log.error("Shadow crypt error for '%s': %s", username, exc)
            return False

    def user_exists(self, username: str) -> bool:
        """Return True if *username* is a valid system user."""
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# BSH Host Service
# ─────────────────────────────────────────────────────────────────────────────

class BSHHostService:
    """
    Core BSH server.  Call start_server() to accept Bluetooth connections.

    Authentication flow
    ───────────────────
      1. BSH password DB lookup first (if the username exists in the DB the
         BSH password is used exclusively — no PAM call is made).
      2. If the username is NOT in the BSH DB, PAM authentication is
         attempted against the OS user database.

    This mirrors the OpenSSH model where local key/password files take
    precedence over PAM.
    """

    def __init__(
        self,
        password_file: str = None,
        channel: int = 1,
    ):
        self._log       = logging.getLogger('BSHServer.HostService')
        self.linux_auth = LinuxAuthService()
        self.crypto     = BSHCrypto()

        self.password_file = password_file or DEFAULT_PW_FILE
        self.password_auth: BSHPasswordAuth | None = None

        self.server_sock        = None
        self.client_sock        = None
        self._client_addr       = None
        self.running            = False
        self.authenticated_user = None        # BSH username
        self.authenticated_sys_user = None    # OS username (may differ)
        self.session_key: bytes | None = None
        self._encrypted         = False
        self._send_lock         = threading.Lock()
        self._connection_count  = 0
        self.bound_channel      = None
        self._runtime_file      = RUNTIME_JSON

        self._load_password_db()

    # ── Initialisation helpers ────────────────────────────────────────────────

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

    def _create_rfcomm_socket(self):
        if _HAS_PYBLUEZ:
            return _pybluez.BluetoothSocket(_pybluez.RFCOMM)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    # ── Main server loop ──────────────────────────────────────────────────────

    def start_server(self, channel: int = 1):
        self._log.info("=" * 60)
        self._log.info("BSH Host Service starting (Linux)")
        self._log.info("PID            : %d", os.getpid())
        try:
            self._log.info("Running as     : %s (UID %d)", pwd.getpwuid(os.getuid()).pw_name, os.getuid())
        except Exception:
            self._log.info("Running as UID : %d", os.getuid())
        self._log.info("Requested channel : %d", channel)
        self._log.info("Auth modes : BSH password DB + PAM/shadow")
        self._log.info("=" * 60)

        self.server_sock = self._create_rfcomm_socket()

        # Bind to any local Bluetooth adapter.
        # If the preferred channel is in use, scan for the next available channel (1-30).
        bdaddr_any = getattr(socket, 'BDADDR_ANY', '00:00:00:00:00:00')
        
        channels_to_try = [channel] if channel > 0 else []
        for c in range(1, 31):
            if c not in channels_to_try:
                channels_to_try.append(c)

        bound = False
        last_exc = None
        for ch in channels_to_try:
            try:
                self.server_sock.bind((bdaddr_any, ch))
                bound = True
                break
            except OSError as exc:
                last_exc = exc
                if exc.errno == 98:  # Address already in use
                    continue
                break
                
        if not bound:
            self._log.error("RFCOMM bind failed: %s", last_exc)
            self._log.error("Ensure BlueZ is running:  systemctl status bluetooth")
            raise last_exc

        actual_channel = self.server_sock.getsockname()[1]
        self.bound_channel = actual_channel

        self.server_sock.listen(1)
        self.server_sock.settimeout(1.0)

        if actual_channel != channel:
            self._log.warning(
                "Requested channel %d but OS assigned channel %d.",
                channel, actual_channel,
            )

        self._log.info("Listening on RFCOMM channel %d (backlog=1)", actual_channel)

        register_sdp_service(self.server_sock, actual_channel)

        mode = "root (full user impersonation)" if _is_root() else "non-root (same-user shell)"
        self._log.info("Shell mode : %s", mode)
        self._log.info("Ready — waiting for Bluetooth connections …")

        self._write_runtime_state(actual_channel)

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
                unregister_sdp_service(self.server_sock)
                break
            except socket.timeout:
                continue
            except Exception as exc:
                if 'timed out' in str(exc).lower():
                    continue
                if self.running:
                    self._log.error("Server accept error: %s", exc, exc_info=True)
                break

        self._log.info("Server loop exited")

    # ── Per-connection handler ────────────────────────────────────────────────

    def handle_client(self, conn_id: int = 0):
        addr = self._client_addr
        try:
            self._log.info("[conn#%d] Starting handshake with %s", conn_id, addr)

            hello_pkt = create_hello_packet({
                'name':     'BSH-Host-Service',
                'version':  '1.0',
                'os':       'Linux',
                'features': ['pty', 'signals', 'password'],
            })
            self.send_packet(hello_pkt)
            self._log.info("[conn#%d] MSG_HELLO sent", conn_id)

            client_hello = self.receive_packet()
            if not client_hello or client_hello.msg_type != MessageType.MSG_HELLO:
                self._log.warning("[conn#%d] Invalid handshake. Closing.", conn_id)
                self._send_failure('Expected MSG_HELLO')
                return

            try:
                hello_data = json.loads(client_hello.payload.decode('utf-8'))
            except Exception:
                self._send_failure('Malformed MSG_HELLO payload')
                return

            username    = hello_data.get('username', '').strip()
            auth_method = hello_data.get('auth_method', 'password')
            client_name = hello_data.get('name', 'unknown')

            self._log.info(
                "[conn#%d] Client='%s'  user='%s'  auth='%s'",
                conn_id, client_name, username, auth_method,
            )

            if not username:
                self._send_failure('No username specified')
                return

            if auth_method != 'password':
                self._log.warning("[conn#%d] Unsupported auth method '%s'", conn_id, auth_method)
                self._send_failure(
                    f"Unsupported auth method: {auth_method!r}. Only 'password' is supported."
                )
                return

            self._log.info("[conn#%d] Starting password auth for '%s'", conn_id, username)
            sys_user = self.authenticate_password(username, conn_id)
            if not sys_user:
                self._log.warning("[conn#%d] Password auth FAILED for '%s'", conn_id, username)
                return

            self.authenticated_user     = username
            self.authenticated_sys_user = sys_user
            self._log.info(
                "[conn#%d] AUTH SUCCESS — bsh_user='%s' sys_user='%s' — starting shell session",
                conn_id, username, sys_user,
            )
            self.start_shell_session(conn_id)

        except Exception as exc:
            self._log.error(
                "[conn#%d] Unhandled exception: %s\n%s",
                conn_id, exc, traceback.format_exc(),
            )
        finally:
            self._log.info("[conn#%d] DISCONNECT", conn_id)
            if self.client_sock:
                try:
                    self.client_sock.close()
                except Exception:
                    pass
                self.client_sock = None
            self.authenticated_user     = None
            self.authenticated_sys_user = None
            self._client_addr           = None
            self.session_key            = None
            self._encrypted             = False

    # ── Password authentication ───────────────────────────────────────────────

    def authenticate_password(self, username: str, conn_id: int = 0) -> str | None:
        """
        Run the BSH password-challenge handshake.

        Returns the OS username to run the shell as, or None on failure.
        """
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

        # ── Authentication path ────────────────────────────────────────────────

        if self.password_auth and username in self.password_auth.users:
            # BSH password DB: verify HMAC proof or plaintext password
            proof = resp_data.get('proof')
            if proof is not None:
                if not self.password_auth.verify_password_proof(username, challenge, proof):
                    self._send_failure('Authentication failed')
                    return None
            else:
                if not self.password_auth.verify_password(username, password):
                    self._send_failure('Authentication failed')
                    return None

            sys_user = self.password_auth.get_system_user(username)

            # Make sure the mapped OS user actually exists
            if not self.linux_auth.user_exists(sys_user):
                self._send_failure(f"Mapped system user '{sys_user}' not found")
                return None

        else:
            # Not in BSH DB — fall back to Linux system auth (PAM / shadow)
            sys_user = username
            if not self.linux_auth.user_exists(sys_user):
                self._send_failure('User not found on this system')
                return None
            if not self.linux_auth.verify_password(sys_user, password):
                self._send_failure('Authentication failed')
                return None

        # ── Issue session key ──────────────────────────────────────────────────
        self.session_key = self.crypto.generate_session_key()

        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_SUCCESS,
            json.dumps({
                'status':      'authenticated',
                'username':    username,
                'session_key': self.session_key.hex(),
            }).encode('utf-8'),
        ))
        self._encrypted = True   # encrypt all subsequent packets
        return sys_user

    # ── Shell session ─────────────────────────────────────────────────────────

    def start_shell_session(self, conn_id: int = 0):
        """Attach a PTY shell and relay packets between client and shell."""
        # Short socket timeout lets the loop re-evaluate shell.is_running()
        self.client_sock.settimeout(0.5)

        sys_user = self.authenticated_sys_user
        shell = make_shell(sys_user)

        try:
            shell.start()
        except Exception as exc:
            self._send_failure(f'Failed to start shell: {exc}')
            return

        import socket as _sock_mod
        welcome = (
            f"\r\nWelcome to BSH — {self.authenticated_user}@{_sock_mod.gethostname()}\r\n"
        )
        self.send_packet(create_data_packet(welcome, MessageType.MSG_DATA_OUT))

        # Background thread: flush shell stdout → client
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

        threading.Thread(target=_shell_to_client, daemon=True, name='bsh-shell-out').start()

        # Main loop: forward client packets → shell
        _exit_reason = 'shell exited'
        while shell.is_running():
            try:
                packet = self.receive_packet()
                if not packet:
                    _exit_reason = 'client disconnected (no packet)'
                    break
                mt = packet.msg_type

                if mt == MessageType.MSG_DATA_IN:
                    shell.write(packet.payload)

                elif mt == MessageType.MSG_INTERRUPT:
                    shell.send_ctrl_c()

                elif mt in (MessageType.MSG_WINDOW_SIZE, MessageType.MSG_WINDOW_RESIZE):
                    import struct
                    if len(packet.payload) >= 4:
                        rows, cols = struct.unpack('!HH', packet.payload[:4])
                        shell.resize_pty(rows, cols)

                elif mt == MessageType.MSG_KEEPALIVE:
                    self.send_packet(BSHPacket(MessageType.MSG_KEEPALIVE))

                elif mt == MessageType.MSG_DISCONNECT:
                    _exit_reason = 'client sent MSG_DISCONNECT'
                    break

            except socket.timeout:
                continue      # re-evaluate shell.is_running()
            except Exception as exc:
                _exit_reason = f'socket error: {exc}'
                break

        self._log.info("[conn] Shell session ended: %s", _exit_reason)
        shell.stop()

    # ── Packet I/O ────────────────────────────────────────────────────────────

    def _send_failure(self, msg: str):
        self.send_packet(BSHPacket(
            MessageType.MSG_AUTH_FAILURE,
            json.dumps({'error': msg}).encode('utf-8'),
        ))

    def send_packet(self, packet: BSHPacket):
        """Encrypt (post-auth) and send a packet over the socket."""
        if self._encrypted and self.session_key:
            encrypted_payload = self.crypto.encrypt_data(self.session_key, packet.payload)
            packet = BSHPacket(packet.msg_type, encrypted_payload)
        raw = packet.to_bytes()
        with self._send_lock:
            self.client_sock.sendall(raw)

    def receive_packet(self) -> BSHPacket | None:
        """Read one packet from the socket, decrypting if a session key is active."""
        header = self._recv_exact(4)
        if not header:
            return None

        if header[0] != BSHPacket.SOF:
            return None

        length = (header[1] << 8) | header[2]
        rest   = self._recv_exact(length + 1)
        if not rest:
            return None

        pkt = BSHPacket.from_bytes(header + rest)
        if pkt and self._encrypted and self.session_key:
            try:
                decrypted = self.crypto.decrypt_data(self.session_key, pkt.payload)
                pkt = BSHPacket(pkt.msg_type, decrypted)
            except Exception as exc:
                self._log.warning("Decryption failed: %s", exc)
                return None
        return pkt

    def _recv_exact(self, size: int) -> bytes | None:
        """Read exactly *size* bytes from the client socket.

        socket.timeout is re-raised so the calling start_shell_session loop
        can handle it with 'except socket.timeout: continue' rather than
        treating it as a disconnect.  All other exceptions return None.
        """
        data = b''
        while len(data) < size:
            try:
                chunk = self.client_sock.recv(size - len(data))
            except socket.timeout:
                raise   # let start_shell_session's except socket.timeout: continue handle it
            except Exception as exc:
                if 'timed out' in str(exc).lower():
                    raise socket.timeout("timed out")
                return None
            if not chunk:
                return None
            data += chunk
        return data

    # ── Runtime state ─────────────────────────────────────────────────────────

    def _write_runtime_state(self, channel: int) -> None:
        state = {
            'bound_channel': channel,
            'pid':           os.getpid(),
            'started_at':    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        try:
            self._runtime_file.parent.mkdir(parents=True, exist_ok=True)
            self._runtime_file.write_text(json.dumps(state, indent=2), encoding='utf-8')
        except Exception as exc:
            self._log.warning("Could not write runtime state: %s", exc)

    def _clear_runtime_state(self) -> None:
        try:
            if self._runtime_file.exists():
                self._runtime_file.unlink()
        except Exception:
            pass

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def stop(self):
        """Gracefully stop the server."""
        self.running = False
        unregister_sdp_service(self.server_sock)
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        self._clear_runtime_state()


# ─────────────────────────────────────────────────────────────────────────────
# Standalone entry point (for quick testing without the service wrapper)
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if not _is_root():
        log.error(
            "Root privileges required (for user impersonation and /etc/shadow access).\n"
            "Run with:  sudo python3 bsh_server_service.py"
        )
        return 1

    host = BSHHostService()
    try:
        host.start_server(channel=1)
    except KeyboardInterrupt:
        host.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
