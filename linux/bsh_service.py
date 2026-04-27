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
BSH Linux Service — runs BSH Host as a systemd-compatible daemon.

Enables proper user impersonation via PTY + setuid/setgid (like OpenSSH).

Installation (installs systemd unit and enables on boot)
──────────────────────────────────────────────────────────
    sudo python3 bsh_service.py install
    sudo python3 bsh_service.py start

Management
──────────
    sudo python3 bsh_service.py status
    sudo python3 bsh_service.py restart
    python3 bsh_service.py logs [--follow] [--lines N]

Uninstallation
──────────────
    sudo python3 bsh_service.py stop
    sudo python3 bsh_service.py remove
"""

import sys
import os
import time
import logging
import json
import argparse
import subprocess
import signal
import threading
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Configuration — SSH-style hybrid approach
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    'base_dir':      '/var/lib/bsh',
    'config_file':   '/etc/bsh/config.json',
    'log_dir':       '/var/log/bsh',
    'log_file':      '/var/log/bsh/bsh_service.log',
    'run_dir':       '/run/bsh',
    'pid_file':      '/run/bsh/bsh.pid',
    'channel':       1,
    'log_level':     'DEBUG',
}

SERVICE_NAME    = 'bsh'
SERVICE_LABEL   = 'BSH Bluetooth Shell Service'
SYSTEMD_UNIT    = f'/etc/systemd/system/{SERVICE_NAME}.service'


def load_config() -> dict:
    """
    Load configuration using SSH-style approach:
      1. Start with hardcoded defaults.
      2. Override with values from config file if it exists.
      3. Config file is optional — defaults always work.
    """
    config = DEFAULT_CONFIG.copy()
    config_path = Path(config['config_file'])

    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as fh:
                user_config = json.load(fh)
                config.update(user_config)
        except Exception as exc:
            print(f"Warning: Could not load config file ({exc}) — using defaults")

    return config


# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(config: dict) -> logging.Logger:
    """Configure root logger → file + stdout."""
    log_dir  = Path(config['log_dir'])
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = Path(config['log_file'])

    level_name = config.get('log_level', 'DEBUG').upper()
    level      = getattr(logging, level_name, logging.DEBUG)

    fmt = logging.Formatter(
        '%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    handlers = []

    try:
        fh = logging.FileHandler(str(log_file), encoding='utf-8')
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        handlers.append(fh)
    except PermissionError:
        print(f"Warning: Cannot write to log file {log_file} — run with sudo")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(level)
    handlers.append(sh)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    for h in handlers:
        root.addHandler(h)

    logger = logging.getLogger('BSHService')
    logger.info("Logging initialised — file: %s  level: %s", log_file, level_name)
    return logger


# ─────────────────────────────────────────────────────────────────────────────
# PID file management
# ─────────────────────────────────────────────────────────────────────────────

def _write_pid(config: dict) -> None:
    pid_path = Path(config['pid_file'])
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()))


def _read_pid(config: dict) -> int | None:
    pid_path = Path(config['pid_file'])
    if pid_path.exists():
        try:
            return int(pid_path.read_text().strip())
        except Exception:
            pass
    return None


def _clear_pid(config: dict) -> None:
    pid_path = Path(config['pid_file'])
    try:
        if pid_path.exists():
            pid_path.unlink()
    except Exception:
        pass


def _is_process_running(pid: int) -> bool:
    """Return True if *pid* is alive."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Daemon run loop
# ─────────────────────────────────────────────────────────────────────────────

def run_daemon(config: dict) -> int:
    """
    Main daemon entry point.

    Starts BSHHostService and blocks until SIGTERM/SIGINT is received.
    """
    logger = setup_logging(config)

    logger.info("=" * 60)
    logger.info("BSH Service starting (Linux daemon)")
    logger.info("PID            : %d", os.getpid())
    logger.info("Channel        : %d", config['channel'])
    logger.info("Log file       : %s", config['log_file'])
    logger.info("Log level      : %s", config.get('log_level', 'DEBUG'))
    logger.info("=" * 60)

    _write_pid(config)

    stop_event = threading.Event()
    bsh_host   = None

    def _handle_signal(signum, _frame):
        sig_name = signal.Signals(signum).name
        logger.info("Signal %s received — shutting down", sig_name)
        stop_event.set()
        if bsh_host:
            bsh_host.stop()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGHUP,  _handle_signal)   # reload config (future)

    logger.info("Importing BSHHostService …")
    try:
        from bsh_server_service import BSHHostService
        logger.info("BSHHostService imported successfully")
    except ImportError as exc:
        logger.error("Failed to import BSHHostService: %s", exc)
        logger.error("Ensure bsh_server_service.py is in the same directory.")
        _clear_pid(config)
        return 1

    try:
        logger.info("Creating BSHHostService instance …")
        bsh_host = BSHHostService(
            channel=config['channel'],
        )
        logger.info("BSHHostService instance created")

        server_thread = threading.Thread(
            target=bsh_host.start_server,
            args=(config['channel'],),
            daemon=True,
            name='bsh-server-main',
        )
        server_thread.start()
        logger.info("BSH server thread started — waiting for stop signal …")

        # Block until a stop signal arrives
        stop_event.wait()

        logger.info("Stop event received — joining server thread …")
        server_thread.join(timeout=5.0)

    except Exception as exc:
        logger.error("Service runtime error: %s", exc, exc_info=True)
    finally:
        _clear_pid(config)
        logger.info("BSH Service exiting")

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Status command
# ─────────────────────────────────────────────────────────────────────────────

def show_status() -> int:
    """Display service status — modelled on 'systemctl status sshd'."""
    print()
    print("=" * 70)
    print(f"  BSH Service Status — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    config  = load_config()
    pid     = _read_pid(config)

    # Check whether the process is actually alive
    if pid and _is_process_running(pid):
        print(f"  ● Service State : RUNNING")
        print(f"  Process ID     : {pid}")
    elif pid:
        print(f"  ○ Service State : DEAD (stale PID file, last PID {pid})")
    else:
        print(f"  ○ Service State : STOPPED")

    print()

    # Read runtime state written by the running server
    runtime_file = Path(config['run_dir']) / 'runtime.json'
    runtime = {}
    if runtime_file.exists():
        try:
            runtime = json.loads(runtime_file.read_text(encoding='utf-8'))
        except Exception:
            pass

    bound_channel  = runtime.get('bound_channel')
    config_channel = config['channel']
    started_at     = runtime.get('started_at', 'unknown')

    def file_status(filepath):
        p = Path(filepath)
        if p.exists():
            size  = p.stat().st_size
            mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            return f"✓ exists  ({size} bytes, modified {mtime})"
        return "⚠ not found"

    print("  Configuration:")
    print(f"    Config file        : {config['config_file']}")
    print(f"    Configured channel : {config_channel}")
    print(f"    Log level          : {config.get('log_level', 'DEBUG')}")

    print()
    print("  Runtime:")
    if bound_channel is not None:
        mismatch = ' ⚠ MISMATCH with config!' if bound_channel != config_channel else ' ✓'
        print(f"    Bound channel      : {bound_channel}{mismatch}")
        print(f"    Started at         : {started_at}")
    else:
        print("    Bound channel      : ⚠ not available (service may not be running)")

    print()
    print("  Files:")
    print(f"    Log file       : {config['log_file']}")
    print(f"                     {file_status(config['log_file'])}")
    print(f"    PID file       : {config['pid_file']}")
    print(f"                     {file_status(config['pid_file'])}")

    print()

    # Check if managed by systemd
    systemd_ok = _systemd_available()
    if systemd_ok:
        print("  Systemd Unit:")
        r = subprocess.run(
            ['systemctl', 'is-active', SERVICE_NAME],
            capture_output=True, text=True,
        )
        unit_state = r.stdout.strip()
        print(f"    Active: {unit_state}")
        r2 = subprocess.run(
            ['systemctl', 'is-enabled', SERVICE_NAME],
            capture_output=True, text=True,
        )
        print(f"    Enabled (on boot): {r2.stdout.strip()}")
        print()

    # Recent log entries
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
# Logs command
# ─────────────────────────────────────────────────────────────────────────────

def show_logs(follow: bool = False, lines: int = 50) -> int:
    """Display service logs, optionally following (tail -f style)."""
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
            print("\n--- Stopped following ---")
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
# Systemd helpers
# ─────────────────────────────────────────────────────────────────────────────

def _systemd_available() -> bool:
    """Return True if systemctl is present in PATH."""
    return subprocess.run(
        ['which', 'systemctl'],
        capture_output=True,
    ).returncode == 0


def _generate_unit_file(config: dict, script_path: str) -> str:
    """Generate the content of the systemd unit file."""
    python_exe = sys.executable
    return f"""\
[Unit]
Description={SERVICE_LABEL}
Documentation=https://github.com/your-org/openbsh
After=network.target bluetooth.target
Wants=bluetooth.target

[Service]
Type=simple
ExecStart={python_exe} {script_path} _run
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bsh

# Security hardening
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths={config['base_dir']} {config['log_dir']} {config['run_dir']}

# BSH requires root for user impersonation (like sshd)
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""


def _setup_environment(config: dict) -> None:
    """Create directories and a default config file."""

    print("\n[1/3] Creating data directories …")
    dirs = [
        Path(config['base_dir']),
        Path(config['log_dir']),
        Path(config['run_dir']),
        Path(config['config_file']).parent,
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {d}")

    print("\n[2/3] Writing default configuration …")
    config_file = Path(config['config_file'])
    if not config_file.exists():
        default_config = {
            'channel':       config['channel'],
            'log_level':     'DEBUG',
            'log_file':      config['log_file'],
        }
        with open(config_file, 'w', encoding='utf-8') as fh:
            json.dump(default_config, fh, indent=2)
        print(f"  ✓ {config_file}")
    else:
        print(f"  — Config already exists: {config_file}")

    print("\n[3/3] Installing systemd unit …")
    script_path = os.path.abspath(sys.argv[0])
    unit_content = _generate_unit_file(config, script_path)

    try:
        with open(SYSTEMD_UNIT, 'w') as fh:
            fh.write(unit_content)
        print(f"  ✓ {SYSTEMD_UNIT}")
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        print("  ✓ systemctl daemon-reload")
    except PermissionError:
        print(f"  ⚠ No permission to write {SYSTEMD_UNIT} — run with sudo")
    except Exception as exc:
        print(f"  ⚠ Could not install unit file: {exc}")

    print()
    print("=" * 60)
    print("Installation complete!")
    print("=" * 60)
    print()
    exe = os.path.basename(sys.argv[0])
    print("Next steps:")
    print(f"  1. Start service  :  sudo python3 {exe} start")
    print(f"           — or —  :  sudo systemctl start {SERVICE_NAME}")
    print(f"  2. Enable on boot :  sudo systemctl enable {SERVICE_NAME}")
    print(f"  3. Check status   :  python3 {exe} status")
    print(f"  4. View logs      :  python3 {exe} logs")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Service control via systemctl
# ─────────────────────────────────────────────────────────────────────────────

def _systemctl(action: str) -> int:
    """Run a systemctl command for the BSH service."""
    try:
        r = subprocess.run(
            ['systemctl', action, SERVICE_NAME],
            check=False,
        )
        return r.returncode
    except FileNotFoundError:
        print("systemctl not found — starting/stopping directly via PID file")
        return _direct_control(action)


def _direct_control(action: str) -> int:
    """Fallback when systemd is not available."""
    config = load_config()
    if action == 'start':
        pid = _read_pid(config)
        if pid and _is_process_running(pid):
            print(f"BSH service is already running (PID {pid})")
            return 0
        script = os.path.abspath(sys.argv[0])
        proc = subprocess.Popen(
            [sys.executable, script, '_run'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(1.0)
        print(f"  ✓ BSH started (PID {proc.pid})")
        return 0

    elif action in ('stop', 'restart'):
        config = load_config()
        pid = _read_pid(config)
        if pid and _is_process_running(pid):
            os.kill(pid, signal.SIGTERM)
            for _ in range(10):
                time.sleep(0.5)
                if not _is_process_running(pid):
                    break
            print("  ✓ BSH stopped")
        else:
            print("  BSH service was not running")

        if action == 'restart':
            time.sleep(0.5)
            return _direct_control('start')
        return 0

    return 1


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _check_root(cmd: str) -> bool:
    """Print an error and return False if not root."""
    if os.geteuid() != 0:
        print(f"Error: '{cmd}' requires root (sudo) privileges.")
        return False
    return True


def main() -> int:
    needs_root = {'install', 'start', 'stop', 'restart', 'remove', '_run'}

    if len(sys.argv) < 2:
        _print_usage()
        return 0

    cmd = sys.argv[1].lower()

    # ── Status / logs — no root needed ────────────────────────────────────────
    if cmd == 'status':
        return show_status()

    if cmd == 'logs':
        parser = argparse.ArgumentParser(description='View BSH service logs')
        parser.add_argument('logs', help='logs command')
        parser.add_argument('--follow', '-f', action='store_true',
                            help='Follow log output (like tail -f / journalctl -f)')
        parser.add_argument('--lines', '-n', type=int, default=50,
                            help='Number of lines to show (default: 50)')
        try:
            args = parser.parse_args()
            return show_logs(follow=args.follow, lines=args.lines)
        except SystemExit:
            return 0

    # ── Internal: actual daemon run loop (called by systemd / _direct_control) ─
    if cmd == '_run':
        if not _check_root(cmd):
            return 1
        config = load_config()
        return run_daemon(config)

    # ── Commands that require root ─────────────────────────────────────────────
    if cmd in needs_root and not _check_root(cmd):
        return 1

    if cmd == 'install':
        config = load_config()
        _setup_environment(config)
        return 0

    if cmd == 'remove':
        # Stop the service first, then delete the unit file
        _systemctl('stop')
        _systemctl('disable')
        try:
            Path(SYSTEMD_UNIT).unlink(missing_ok=True)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            print(f"  ✓ Removed {SYSTEMD_UNIT}")
        except Exception as exc:
            print(f"  ⚠ Could not remove unit file: {exc}")
        return 0

    if cmd in ('start', 'stop', 'restart'):
        if _systemd_available():
            return _systemctl(cmd)
        return _direct_control(cmd)

    print(f"Unknown command: {cmd!r}")
    _print_usage()
    return 1


def _print_usage():
    exe = os.path.basename(sys.argv[0])
    print()
    print("BSH Linux Service Control")
    print("=" * 60)
    print(f"\nUsage:  {exe} <command>\n")
    print("Service Management (require sudo):")
    print("  install         Install directories, config, and systemd unit")
    print("  start           Start the service")
    print("  stop            Stop the service")
    print("  restart         Restart the service")
    print("  remove          Uninstall the service\n")
    print("Monitoring (no sudo needed):")
    print("  status          Show service status and configuration")
    print("  logs            Show recent logs (last 50 lines)")
    print("  logs -n 100     Show last 100 lines")
    print("  logs --follow   Follow logs in real-time")
    print("=" * 60)


if __name__ == '__main__':
    sys.exit(main())
