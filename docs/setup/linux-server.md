# Linux Server Setup

OpenBSH runs as a native systemd service on Linux, providing seamless, unprivileged SSH-style access over Bluetooth.

## Prerequisites

Before installing the OpenBSH server, ensure that Bluetooth is enabled on your system and the necessary development libraries are installed.

### Install Dependencies

=== "Debian / Ubuntu"
    ```bash
    sudo apt update
    sudo apt install python3 python3-pip libbluetooth-dev libpam0g-dev bluez
    ```

=== "Fedora / RHEL"
    ```bash
    sudo dnf install python3 python3-pip bluez-libs-devel pam-devel bluez
    ```

=== "Arch Linux"
    ```bash
    sudo pacman -S python python-pip bluez bluez-libs bluez-utils
    ```

### Verify Bluetooth Service
Make sure BlueZ is running:
```bash
sudo systemctl enable --now bluetooth
bluetoothctl show          # verify adapter is detected
```

---

## Installation

The Linux port includes a unified install script that handles copying files, creating directories, and installing the systemd unit.

1. Clone or download the OpenBSH repository.
2. Navigate to the `linux/` directory.
3. Run the installer script:

```bash
sudo bash install.sh
```

### What the script does:
- Installs Python dependencies (`cryptography`, `python-pam`, `PyBluez`) globally.
- Copies the core BSH python files to `/opt/bsh/`.
- Creates necessary state directories: `/var/lib/bsh/`, `/var/log/bsh/`, `/run/bsh/`, `/etc/bsh/`.
- Generates a default configuration file at `/etc/bsh/config.json`.
- Installs and enables the `bsh.service` systemd unit.

> [!NOTE]
> OpenBSH **must** run as root (UID 0) to properly hook into PAM and to impersonate the logged-in user via `setuid` / `setgid`.

---

## Configuration

The main configuration file is located at `/etc/bsh/config.json`.

```json
{
  "channel":   1,
  "log_level": "DEBUG",
  "log_file":  "/var/log/bsh/bsh_service.log"
}
```

| Key | Default | Description |
|---|---|---|
| `channel` | `1` | RFCOMM channel to bind. The server auto-scans 1–30 if the preferred channel is busy. |
| `log_level` | `DEBUG` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `log_file` | `/var/log/bsh/bsh_service.log` | Path to the log file. |

If you modify this file, you must restart the service:
```bash
sudo systemctl restart bsh
```

---

## Service Management

OpenBSH on Linux relies on `systemd` for lifecycle management, though you can use the built-in python script as well.

### Using Systemd (Recommended)
```bash
sudo systemctl start   bsh
sudo systemctl stop    bsh
sudo systemctl restart bsh
systemctl status       bsh
```

### Viewing Logs
Logs are managed by both systemd's journal and a local log file.
```bash
# View systemd journal
journalctl -u bsh -f

# View file logs
tail -f /var/log/bsh/bsh_service.log
```

---

## Bluetooth SDP Advertisement (Optional)

By default, the BSH server attempts to register itself in the BlueZ SDP database so clients can auto-discover its RFCOMM channel. On modern BlueZ 5+ systems, `bluetoothd` must be started with the `--compat` flag for SDP registration to work.

A helper script is included to configure this automatically:

```bash
sudo bash /opt/bsh/setup_bluetooth_compat.sh
```

This script:
1. Detects the `bluetoothd` binary path.
2. Writes a systemd drop-in at `/etc/systemd/system/bluetooth.service.d/compat.conf` that adds the `--compat` flag.
3. Restarts `bluetoothd` and verifies the flag is active.

> [!NOTE]
> Without `--compat`, SDP advertisement is skipped and clients must specify the channel explicitly using the `-p` flag (e.g. `bsh_client_linux.py user@MAC -p 1`).

---

## User Management

By default, OpenBSH authenticates against native Linux OS accounts via PAM
(or `/etc/shadow` as a fallback). **Any existing Linux system user can log in
over BSH using their regular system password** — no additional user setup is
required.

> [!NOTE]
> A standalone BSH password database (`bsh_password.py`) is planned for a
> future release. It will allow granting Bluetooth access using credentials
> independent of system passwords. Until then, use native OS accounts.

> [!IMPORTANT]
> When adding a standalone user (in a future release), the username must
> either perfectly match an existing system user, OR you must explicitly map
> it to an existing system user. If the mapping does not exist, the shell
> will fail to spawn.
