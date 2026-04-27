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
  "channel":       1,
  "log_level":     "DEBUG",
  "password_file": "/var/lib/bsh/passwords",
  "log_file":      "/var/log/bsh/bsh_service.log"
}
```

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

## User Management

By default, OpenBSH will attempt to authenticate against the native Linux PAM module (or fallback to `/etc/shadow`). However, you can manage standalone BSH users using the built-in password database.

```bash
# Add a standalone BSH user
sudo python3 /opt/bsh/bsh_password.py adduser alice

# Add a BSH user mapped to a specific system user
sudo python3 /opt/bsh/bsh_password.py adduser bsh_alice --system-user alice

# List users
sudo python3 /opt/bsh/bsh_password.py list

# Change password
sudo python3 /opt/bsh/bsh_password.py passwd alice

# Delete user
sudo python3 /opt/bsh/bsh_password.py deluser alice
```

> [!IMPORTANT]
> When adding a standalone user, the username must either perfectly match an existing system user (e.g., `alice`), OR you must explicitly map it to an existing system user using `--system-user`. If the mapping does not exist, the shell will fail to spawn.
