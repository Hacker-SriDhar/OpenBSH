# OpenBSH Server — Linux Port

A fully functional Linux port of the BSH (Bluetooth Shell) service.
Provides secure, SSH-style remote shell access over Bluetooth RFCOMM.

---

## Architecture

```
bsh_service.py          ← Systemd daemon wrapper  (replaces Windows Service)
bsh_server_service.py   ← Core BSH server logic   (Linux rewrite)
bsh_protocol.py         ← Wire protocol            (unchanged — cross-platform)
bsh_password.py         ← BSH password DB          (POSIX chmod instead of Win32 DACL)
bsh_crypto.py           ← AES-256-GCM + PBKDF2     (unchanged — cross-platform)
bsh.service             ← Systemd unit file
install.sh              ← One-shot install script
requirements.txt        ← Python dependencies
```

### Key differences from the Windows version

| Component | Windows | Linux |
|---|---|---|
| Service host | `win32serviceutil` (pywin32) | systemd + signal handlers |
| RFCOMM socket | Custom Winsock `AF_BTH` via ctypes | `socket.AF_BLUETOOTH` (stdlib) |
| SDP advertisement | `WSASetServiceW` via ctypes | `bluetooth.advertise_service` (PyBluez) |
| Shell | `CreateProcessAsUser` (impersonated) | `pty.openpty` + `fork` + `setuid`/`setgid` |
| System auth | `LogonUserW` via ctypes | PAM (`python-pam`) / `/etc/shadow` fallback |
| File permissions | Win32 DACL (SYSTEM + Admins) | POSIX `chmod 0o600` |
| Data dir | `C:\ProgramData\BSH` | `/var/lib/bsh` |
| Logs | `C:\ProgramData\BSH\logs\` | `/var/log/bsh/` |
| PID / runtime | Registry / runtime.json | `/run/bsh/` |

---

## Quick Start

### 1. Prerequisites

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install python3 python3-pip libbluetooth-dev libpam0g-dev bluez

# Fedora / RHEL
sudo dnf install python3 python3-pip bluez-libs-devel pam-devel bluez

# Arch Linux
sudo pacman -S python python-pip bluez bluez-libs bluez-utils
```

Make sure BlueZ is running:
```bash
sudo systemctl enable --now bluetooth
bluetoothctl show          # verify adapter is detected
```

### 2. Install (one command)

```bash
sudo bash install.sh
```

This will:
- Install Python packages (`cryptography`, `python-pam`, `PyBluez` when available for SDP discovery/advertisement)
- Copy BSH files to `/opt/bsh/`
- Create `/var/lib/bsh/`, `/var/log/bsh/`, `/run/bsh/`, `/etc/bsh/`
- Write a default `/etc/bsh/config.json`
- Install and enable the `bsh.service` systemd unit

### 3. Authenticate as a system user

By default BSH authenticates against native OS accounts via PAM or `/etc/shadow`.
Simply use an existing Linux username and password when connecting.

### 4. Start the service

```bash
sudo systemctl start bsh
systemctl status bsh
```

### 5. Connect from a client

From any BSH-compatible client (Linux or Windows):
```bash
python3 bsh_client_linux.py alice@AA:BB:CC:DD:EE:FF
# or
python bsh_client_windows.py alice@AA:BB:CC:DD:EE:FF
```

---

## Management Commands

```bash
# Via bsh_service.py (no systemd required)
sudo python3 /opt/bsh/bsh_service.py install    # First-time setup
sudo python3 /opt/bsh/bsh_service.py start
sudo python3 /opt/bsh/bsh_service.py stop
sudo python3 /opt/bsh/bsh_service.py restart
      python3 /opt/bsh/bsh_service.py status    # No sudo needed
      python3 /opt/bsh/bsh_service.py logs
      python3 /opt/bsh/bsh_service.py logs -f   # Follow (like tail -f)
sudo python3 /opt/bsh/bsh_service.py remove

# Via systemd
sudo systemctl start   bsh
sudo systemctl stop    bsh
sudo systemctl restart bsh
     systemctl status  bsh
     journalctl -u bsh -f
```

---

## User management

By default, OpenBSH authenticates against native Linux OS accounts via PAM
or `/etc/shadow`. Simply use an existing Linux username and its system password
when connecting from a client.

> [!NOTE]
> A standalone BSH password database (`bsh_password.py`) is planned for a
> future release. It will allow granting BSH access using separate credentials
> that do not match the system password.

---

## Configuration

Edit `/etc/bsh/config.json`:

```json
{
  "channel":       1,
  "log_level":     "DEBUG",
  "password_file": "/var/lib/bsh/passwords",
  "log_file":      "/var/log/bsh/bsh_service.log"
}
```

Then restart: `sudo systemctl restart bsh`

---

## Authentication flow

```
Client                          Server
  │── MSG_HELLO ──────────────────►│  {username, auth_method="password", name, version}
  │◄── MSG_HELLO ──────────────────│  {name, version, os, features}
  │── MSG_AUTH_LOGIN ─────────────►│  {username, password (plaintext)}
  │◄── MSG_AUTH_SUCCESS ───────────│  {status, username, session_key (hex)}
  │     OR MSG_AUTH_FAILURE ───────│  {error}
  │═══════ Encrypted shell I/O ════│
```

The server verifies credentials via **PAM** (`python-pam`) and, if PAM is
unavailable, falls back to `/etc/shadow` directly (requires root).

---

## Security notes

- The service **must run as root** (UID 0) to impersonate users via
  `os.setuid()`/`os.setgid()` — identical to how OpenSSH's `sshd` works.
- All traffic after `MSG_AUTH_SUCCESS` is encrypted with AES-256-GCM using a
  session key negotiated during authentication.
- The BSH password file is stored at `/var/lib/bsh/passwords` with mode `0600`
  (owner-root-only).
- Bluetooth RFCOMM provides the link-layer; for additional security, enable
  Bluetooth pairing/bonding so only trusted devices can connect.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: bluetooth` | PyBluez not installed — SDP advertisement/discovery is reduced, but direct channel connections still work |
| `RFCOMM bind failed` | BlueZ not running: `sudo systemctl start bluetooth` |
| `PAM auth failed` | Install python-pam or run as root for shadow fallback |
| `User not found` | Use a valid local Linux OS account username |
| `Permission denied` on log/data dirs | Run service as root (`sudo systemctl start bsh`) |
| No BT adapter detected | `hciconfig -a` to list adapters; `bluetoothctl power on` |
