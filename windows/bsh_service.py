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
BSH Windows Service — runs BSH Host as a Windows Service with SYSTEM privileges.

Enables proper user impersonation via CreateProcessAsUser (like OpenSSH).

Installation
────────────
    python bsh_service.py install
    python bsh_service.py start

Management
──────────
    python bsh_service.py status
    python bsh_service.py restart
    python bsh_service.py logs [--follow] [--lines N]

Uninstallation
──────────────
    python bsh_service.py stop
    python bsh_service.py remove
"""

import sys
import os
import time
import logging
import json
import winreg
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32api
except ImportError:
    print("Error: pywin32 is not installed.")
    print("Install with:  pip install pywin32")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration — SSH-style hybrid approach
# ─────────────────────────────────────────────────────────────────────────────

# Hardcoded defaults (compiled into binary, used as fallbacks)
DEFAULT_CONFIG = {
    'base_dir':        r'C:\ProgramData\BSH',
    'config_file':     r'C:\ProgramData\BSH\config.json',
    'log_dir':         r'C:\ProgramData\BSH\logs',
    'log_file':        r'C:\ProgramData\BSH\logs\bsh_service.log',
    'channel':         1,
    'password_file':   r'C:\ProgramData\BSH\passwords',
    'log_level':       'DEBUG',   # DEBUG | INFO | WARNING | ERROR
}


def load_config() -> dict:
    """
    Load configuration using SSH-style approach:
    1. Start with hardcoded defaults
    2. Override with values from config file if it exists
    3. Config file is optional — defaults always work

    This works identically whether running as Python script or compiled binary.
    """
    config = DEFAULT_CONFIG.copy()
    config_path = Path(config['config_file'])

    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as fh:
                user_config = json.load(fh)
                config.update(user_config)
        except Exception as exc:
            # Can't use logger here (not set up yet) — safe to print
            print(f"Warning: Could not load config file ({exc}) — using defaults")

    return config


# ─────────────────────────────────────────────────────────────────────────────
# Service class
# ─────────────────────────────────────────────────────────────────────────────

class BSHService(win32serviceutil.ServiceFramework):
    r"""
    Windows Service wrapper for the BSH (Bluetooth Shell) Host.

    Runs as NT AUTHORITY\SYSTEM with the following privileges granted
    via the RequiredPrivileges registry value:
        SeAssignPrimaryTokenPrivilege  — spawn processes as other users
        SeIncreaseQuotaPrivilege       — adjust process memory quotas
        SeTcbPrivilege                 — act as part of the OS
    """

    _svc_name_         = "BSHService"
    _svc_display_name_ = "BSH Bluetooth Shell Service"
    _svc_description_  = (
        "Provides secure Bluetooth-based remote shell access with "
        "password authentication, modelled on SSH "
        "over Bluetooth (Bluetooth Shell — BSH)."
    )

    # CRITICAL: must match  <module_name>.<ClassName>  so pywin32 can locate
    # the class when the SCM starts the service.
    _svc_reg_class_ = "bsh_service.BSHService"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.config     = load_config()
        self._setup_logging()
        self.bsh_host   = None
        self.logger.info("BSHService.__init__ complete")

    # ── Logging ───────────────────────────────────────────────────────────────

    def _setup_logging(self):
        """
        Configure the ROOT logger so that every module (including
        bsh_server_service) writes to the same file + stdout handlers.
        """
        log_dir  = Path(self.config['log_dir'])
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = Path(self.config['log_file'])

        level_name = self.config.get('log_level', 'DEBUG').upper()
        level      = getattr(logging, level_name, logging.DEBUG)

        # Build a single formatter used by all handlers
        fmt = logging.Formatter(
            '%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

        # File handler — rotates automatically on each service start
        fh = logging.FileHandler(str(log_file), encoding='utf-8')
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)   # always log everything to the file

        handlers = [fh]

        # Stdout handler — only useful when not running as a headless service,
        # but harmless when stdout is None (pywin32 redirects it to NUL).
        if sys.stdout is not None:
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(fmt)
            sh.setLevel(level)
            handlers.append(sh)

        # Configure the ROOT logger — this propagates to all child loggers
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        # Remove any handlers that basicConfig may have already installed
        root.handlers.clear()
        for h in handlers:
            root.addHandler(h)

        self.logger = logging.getLogger('BSHService')
        self.logger.info(
            "Logging initialised — file: %s  level: %s", log_file, level_name
        )

    # ── SCM callbacks ─────────────────────────────────────────────────────────

    def SvcStop(self):
        """Called by SCM when a stop is requested."""
        self.logger.info("Stop requested by SCM")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

        if self.bsh_host:
            try:
                self.logger.info("Calling BSHHostService.stop()")
                self.bsh_host.stop()
                self.logger.info("BSHHostService.stop() returned")
            except Exception as exc:
                self.logger.error("Error stopping BSH host: %s", exc, exc_info=True)

    def SvcDoRun(self):
        """Main service entry point — called when the service starts."""
        self.logger.info("=" * 60)
        self.logger.info("BSH Service SvcDoRun — starting")
        self.logger.info("PID            : %d", os.getpid())
        self.logger.info("Running as     : %s", os.environ.get('USERNAME', 'SYSTEM'))
        self.logger.info("Channel        : %d", self.config['channel'])
        self.logger.info("Password file  : %s", self.config['password_file'])
        self.logger.info("Log file       : %s", self.config['log_file'])
        self.logger.info("Log level      : %s", self.config.get('log_level', 'DEBUG'))
        self.logger.info("=" * 60)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ''),
        )

        # Delayed import so the module is only loaded when the service runs,
        # not during installation.
        self.logger.info("Importing BSHHostService …")
        try:
            from bsh_server_service import BSHHostService
            self.logger.info("BSHHostService imported successfully")
        except ImportError as exc:
            self.logger.error("Failed to import BSHHostService: %s", exc, exc_info=True)
            self.logger.error("Ensure bsh_server_service.py is in the same directory.")
            servicemanager.LogErrorMsg(f"BSH Service import error: {exc}")
            return

        try:
            self.logger.info("Creating BSHHostService instance …")
            self.bsh_host = BSHHostService(
                password_file=self.config['password_file'],
                channel=self.config['channel'],
            )
            self.logger.info("BSHHostService instance created")

            import threading
            server_thread = threading.Thread(
                target=self.bsh_host.start_server,
                args=(self.config['channel'],),
                daemon=True,
                name='bsh-server-main',
            )
            server_thread.start()
            self.logger.info("BSH server thread started (name=%s)", server_thread.name)

            self.logger.info("BSH Host started successfully — waiting for stop event …")

            # Block until the stop event is signalled
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            self.logger.info("Stop event received — BSH Service shutting down …")

        except Exception as exc:
            self.logger.error("Service runtime error: %s", exc, exc_info=True)
            servicemanager.LogErrorMsg(f"BSH Service error: {exc}")

        self.logger.info("SvcDoRun exiting")


# ─────────────────────────────────────────────────────────────────────────────
# Status command — shows service state and configuration
# ─────────────────────────────────────────────────────────────────────────────

def show_status():
    """
    Display service status similar to 'systemctl status sshd'.
    Shows: state, PID, channel, config paths, recent log entries.
    """
    print()
    print("=" * 70)
    print(f"  BSH Service Status — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    # Check service state
    try:
        status = win32serviceutil.QueryServiceStatus(BSHService._svc_name_)
        state_map = {
            win32service.SERVICE_STOPPED:         "STOPPED",
            win32service.SERVICE_START_PENDING:   "STARTING",
            win32service.SERVICE_STOP_PENDING:    "STOPPING",
            win32service.SERVICE_RUNNING:         "RUNNING",
            win32service.SERVICE_CONTINUE_PENDING:"RESUMING",
            win32service.SERVICE_PAUSE_PENDING:   "PAUSING",
            win32service.SERVICE_PAUSED:          "PAUSED",
        }
        state = state_map.get(status[1], "UNKNOWN")
        pid   = status[2]

        state_symbol = "●" if state == "RUNNING" else "○"
        print(f"  {state_symbol} Service State: {state}")
        if pid:
            print(f"  Process ID   : {pid}")
    except Exception as exc:
        print(f"  ✗ Service not installed or inaccessible: {exc}")
        return 1

    print()

    config = load_config()

    # Read runtime state written by the running server.
    # This contains the *actual* bound channel which may differ from the
    # config value because Windows RFCOMM assigns channels dynamically.
    runtime_file = Path(r'C:\ProgramData\BSH\runtime.json')
    runtime = {}
    if runtime_file.exists():
        try:
            runtime = json.loads(runtime_file.read_text(encoding='utf-8'))
        except Exception:
            pass

    bound_channel   = runtime.get('bound_channel')
    config_channel  = config['channel']
    started_at      = runtime.get('started_at', 'unknown')
    runtime_pid     = runtime.get('pid')

    def file_status(filepath):
        p = Path(filepath)
        if p.exists():
            size = p.stat().st_size
            mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            return f"✓ exists  ({size} bytes, modified {mtime})"
        return "⚠ not found"

    print("  Configuration (from config.json):")
    print(f"    Configured channel : {config_channel}")
    print(f"    Log level          : {config.get('log_level', 'DEBUG')}")

    print()
    print("  Runtime (actual values while service is running):")
    if bound_channel is not None:
        mismatch = ' ⚠ MISMATCH with config!' if bound_channel != config_channel else ' ✓'
        print(f"    Bound channel      : {bound_channel}{mismatch}")
        print(f"    Started at         : {started_at}")
        if runtime_pid:
            print(f"    Server PID         : {runtime_pid}")
    else:
        print("    Bound channel      : ⚠ not available (service may not be running or just started)")

    print()
    print("  Files:")
    print(f"    Password File  : {config['password_file']}")
    print(f"                     {file_status(config['password_file'])}")
    print(f"    Log File       : {config['log_file']}")
    print(f"                     {file_status(config['log_file'])}")

    print()

    # Show recent log entries
    log_file = Path(config['log_file'])
    if log_file.exists():
        print("  Recent Logs (last 20 lines):")
        print("  " + "─" * 66)
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as fh:
                lines = fh.readlines()
                for line in lines[-20:]:
                    print(f"    {line.rstrip()}")
        except Exception as exc:
            print(f"    ⚠ Could not read log file: {exc}")
    else:
        print(f"  Log file not found: {log_file}")

    print()
    print("=" * 70)
    print()
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Logs command — tail service logs
# ─────────────────────────────────────────────────────────────────────────────

def show_logs(follow=False, lines=50):
    """
    Display service logs, optionally following (tail -f style).
    Similar to 'journalctl -u sshd -f'.
    """
    config   = load_config()
    log_file = Path(config['log_file'])

    if not log_file.exists():
        print(f"✗ Log file not found: {log_file}")
        return 1

    print()
    print(f"Showing logs from: {log_file}")
    print("=" * 70)
    print()

    if follow:
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as fh:
                all_lines = fh.readlines()
                for line in all_lines[-lines:]:
                    print(line.rstrip())

                print()
                print("--- Following log (Ctrl+C to stop) ---")
                print()

                while True:
                    line = fh.readline()
                    if line:
                        print(line.rstrip())
                    else:
                        time.sleep(0.1)
        except KeyboardInterrupt:
            print()
            print("--- Stopped following ---")
            return 0
        except Exception as exc:
            print(f"✗ Error reading log file: {exc}")
            return 1
    else:
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as fh:
                all_lines = fh.readlines()
                for line in all_lines[-lines:]:
                    print(line.rstrip())
        except Exception as exc:
            print(f"✗ Error reading log file: {exc}")
            return 1

    print()
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Post-install environment setup
# ─────────────────────────────────────────────────────────────────────────────

def _setup_environment() -> None:
    """
    Run after pywin32 creates the service registry keys.

    1. Set RequiredPrivileges in the registry.
    2. Create data directories and a default config.
    """
    config = load_config()

    print("\n[1/3] Requesting service privileges …")
    reg_path   = rf"SYSTEM\CurrentControlSet\Services\{BSHService._svc_name_}"
    privileges = [
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeTcbPrivilege",
    ]
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "RequiredPrivileges", 0, winreg.REG_MULTI_SZ, privileges)
        winreg.CloseKey(key)
        print("  ✓ RequiredPrivileges set in registry")
    except Exception as exc:
        print(f"  ⚠ Could not write RequiredPrivileges: {exc}")

    print("\n[2/3] Creating data directories …")
    dirs = [
        Path(config['base_dir']),
        Path(config['log_dir']),
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {d}")

    print("\n[3/3] Writing default configuration …")
    config_file = Path(config['config_file'])
    if not config_file.exists():
        default_config = {
            'channel':         1,
            'log_level':       'DEBUG',
            'password_file':   config['password_file'],
            'log_file':        config['log_file'],
        }
        with open(config_file, 'w', encoding='utf-8') as fh:
            json.dump(default_config, fh, indent=2)
        print(f"  ✓ {config_file}")
    else:
        print(f"  — Config already exists: {config_file}")

    print()
    print("=" * 60)
    print("Installation complete!")
    print("=" * 60)
    print()
    # Detect whether we are running as a compiled .exe or a .py script
    exe = os.path.basename(getattr(sys, "frozen", False) and sys.executable or sys.argv[0])
    print("Next steps:")
    print(f"  1. Start the service  :  {exe} start")
    print(f"  2. Check status       :  {exe} status")
    print(f"  3. View logs          :  {exe} logs")
    print()
    print("Add password users with:")
    print(r"  bsh-passwd adduser <username>")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _fix_service_registry() -> None:
    """
    After pywin32 installs the service, correct two registry values that
    often cause 'disabled / no enabled devices' (error 1067/1069):
      - Start      → 2  (SERVICE_AUTO_START)
      - ObjectName → LocalSystem  (run as SYSTEM, not a named account)
    Also ensures the ImagePath is set correctly for a compiled .exe.
    """
    svc_name = BSHService._svc_name_
    reg_path  = rf"SYSTEM\CurrentControlSet\Services\{svc_name}"
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, reg_path, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
        )

        # Ensure Start = 2 (AUTO_START). pywin32 sometimes sets 3 (DEMAND) or 4 (DISABLED).
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 2)

        # Ensure ObjectName = LocalSystem so the SCM can launch it without credentials.
        winreg.SetValueEx(key, "ObjectName", 0, winreg.REG_SZ, "LocalSystem")

        # If running as a compiled binary, fix ImagePath to the actual .exe path.
        if getattr(sys, "frozen", False):
            exe_path = sys.executable
            # ImagePath must be quoted if it contains spaces
            if " " in exe_path:
                exe_path = f'"{exe_path}"'
            winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, exe_path)
            print(f"  ✓ ImagePath set to: {exe_path}")

        winreg.CloseKey(key)
        print("  ✓ Registry: Start=AUTO_START, ObjectName=LocalSystem")
    except Exception as exc:
        print(f"  ⚠ Could not fix registry values: {exc}")


def _wait_for_service_deletion(svc_name: str, timeout: int = 10) -> bool:
    """
    Poll SCM until the old service entry disappears (error 1060 = not found).
    Returns True when it is gone, False on timeout.
    """
    import ctypes
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            win32serviceutil.QueryServiceStatus(svc_name)
            time.sleep(0.5)
        except Exception as exc:
            # win32service.error 1060 = ERROR_SERVICE_DOES_NOT_EXIST
            if "1060" in str(exc) or "does not exist" in str(exc).lower():
                return True
            time.sleep(0.5)
    return False


def _safe_install() -> int:
    """
    Install the service, handling the common 'marked for deletion' (1072) error.

    Flow:
      1. Try normal install.
      2. If error 1072 (marked for deletion):
         a. Stop any running instance.
         b. Kill any process holding the binary open.
         c. Wait up to 10 s for SCM to clear the old entry.
         d. Retry the install once.
      3. Fix registry Start/ObjectName values.
      4. Run _setup_environment().
    """
    svc_name = BSHService._svc_name_

    def do_install():
        win32serviceutil.HandleCommandLine(BSHService)

    # ── First attempt ─────────────────────────────────────────────────────────
    install_ok = False
    try:
        do_install()
        install_ok = True
    except Exception as exc:
        err_str = str(exc)
        if "1072" in err_str or "marked for deletion" in err_str.lower():
            print()
            print("  ⚠ Previous service entry is still pending deletion.")
            print("  Attempting to clean up and retry …")

            # Stop running service if any
            try:
                win32serviceutil.StopService(svc_name)
                time.sleep(1)
                print("  ✓ Stopped running service")
            except Exception:
                pass

            # Wait for SCM to release the old entry
            print("  Waiting for SCM to release old service entry …", end="", flush=True)
            cleared = _wait_for_service_deletion(svc_name, timeout=12)
            if cleared:
                print(" done")
            else:
                print(" timed out")
                print()
                print("  SCM has not released the old service yet.")
                print("  Please REBOOT and run  bsh.exe install  again.")
                print("  (This is a Windows SCM limitation — not a BSH bug.)")
                return 1

            # ── Retry install ─────────────────────────────────────────────────
            try:
                do_install()
                install_ok = True
                print("  ✓ Service installed on retry")
            except Exception as exc2:
                print(f"  ✗ Install failed on retry: {exc2}")
                print()
                print("  If the error persists, please reboot and try again.")
                return 1
        else:
            print(f"  ✗ Install error: {exc}")
            return 1

    if install_ok:
        # Fix Start type and ObjectName before _setup_environment prints "Next steps"
        print()
        print("[0/3] Fixing service registry values …")
        _fix_service_registry()
        _setup_environment()

    return 0


def main() -> int:
    # ── Admin check ───────────────────────────────────────────────────────────
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    needs_admin = {'install', 'remove', 'update', 'start', 'stop', 'restart'}

    # ── Handle status / logs without admin ────────────────────────────────────
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()

        if cmd == 'status':
            return show_status()

        if cmd == 'logs':
            parser = argparse.ArgumentParser(description='View BSH service logs')
            parser.add_argument('logs', help='logs command')
            parser.add_argument('--follow', '-f', action='store_true',
                                help='Follow log output (like tail -f)')
            parser.add_argument('--lines', '-n', type=int, default=50,
                                help='Number of lines to show (default: 50)')
            try:
                args = parser.parse_args()
                return show_logs(follow=args.follow, lines=args.lines)
            except SystemExit:
                return 0

        if cmd in needs_admin and not is_admin:
            print("Error: Administrator privileges required for this command.")
            print("Please right-click and choose 'Run as Administrator'.")
            return 1

        # ── install: use robust _safe_install() ──────────────────────────────
        if cmd in ('install', 'update'):
            return _safe_install()

        # ── remove: stop first, then remove ──────────────────────────────────
        if cmd == 'remove':
            try:
                win32serviceutil.StopService(BSHService._svc_name_)
                print("  ✓ Service stopped")
                time.sleep(1)
            except Exception:
                pass
            try:
                win32serviceutil.HandleCommandLine(BSHService)
            except Exception as exc:
                print(f"Error: {exc}")
                return 1
            return 0

    # ── No args: try SCM dispatcher, fall back to help ────────────────────────
    if len(sys.argv) == 1:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(BSHService)
            servicemanager.StartServiceCtrlDispatcher()
            return 0
        except Exception:
            exe = os.path.basename(
                getattr(sys, "frozen", False) and sys.executable or sys.argv[0]
            )
            print("BSH Windows Service Control")
            print("=" * 60)
            print(f"\nUsage:  {exe} <command>\n")
            print("Service Management:")
            print("  install         Install the service")
            print("  start           Start the service")
            print("  stop            Stop the service")
            print("  restart         Restart the service")
            print("  remove          Uninstall the service\n")
            print("Monitoring:")
            print("  status          Show service status and configuration")
            print("  logs            Show recent logs (last 50 lines)")
            print("  logs -n 100     Show last 100 lines")
            print("  logs --follow   Follow logs in real-time")
            print("=" * 60)
            return 0

    # ── All other commands (start, stop, restart) → pywin32 ──────────────────
    try:
        win32serviceutil.HandleCommandLine(BSHService)
    except Exception as exc:
        print(f"Error: {exc}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())