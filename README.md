# OpenBSH: Bluetooth Shell

**OpenBSH** is a robust, cross-platform Bluetooth Shell service. It provides secure, SSH-style remote shell access over Bluetooth RFCOMM, enabling powerful out-of-band management for systems where traditional network access (Wi-Fi, Ethernet) is unavailable, restricted, or compromised.

---

## Key Features

- **Cross-Platform:** Servers run natively as a Windows Service or a Linux `systemd` daemon.
- **Enterprise-Grade Security:** All post-authentication traffic is encrypted using **AES-256-GCM** with a fresh random 32-byte session key for each session.
- **Native OS Authentication:** Authenticates against Windows local accounts via `LogonUserW`, or Linux PAM with `/etc/shadow` fallback when applicable.
- **SSH-Style PTY Experience:** Enjoy an interactive shell experience with pseudo-terminal (PTY) emulation, supporting standard shell utilities (like `vim`, `nano`, `htop`), command history, and continuous output.
- **Zero-Install Client:** Lightweight, portable Python clients for both Windows and Linux.

---

## Documentation

Full documentation is hosted using MkDocs. You can view the comprehensive documentation by running MkDocs locally or visiting the GitHub Pages site (if configured).

```bash
# Run documentation locally
pip install mkdocs mkdocs-material
mkdocs serve
```

---

## Quick Start: Server Setup

### Windows Server

The Windows server runs as a background service and integrates directly with the OS for authentication and impersonation.

1. Open an **Administrator** Command Prompt/PowerShell.
2. Navigate to the `windows/` directory.
3. Install dependencies: `pip install pywin32 cryptography`
4. Install and start the service:
   ```powershell
   python bsh_service.py install
   python bsh_service.py start
   ```

### Linux Server

The Linux server runs as a `systemd` daemon and handles PTY emulation securely by dropping root privileges to the authenticated user.

1. Navigate to the `linux/` directory.
2. Run the provided install script:
   ```bash
   sudo bash install.sh
   ```
3. Ensure the service is running:
   ```bash
   sudo systemctl status bsh
   ```

---

## Quick Start: Client Usage

> **Prerequisite:** Before the client can initiate a connection, the client device and the server device **must be paired and connected** via the standard Bluetooth settings of your operating system.

The OpenBSH client provides the interactive terminal interface. You must use the script matching your OS to ensure correct terminal handling.

1. Navigate to the `Client/` directory.
2. Install dependencies:
   - **Windows:** `pip install cryptography`
   - **Linux:** `sudo apt install libbluetooth-dev` and `pip3 install cryptography`

### Connecting to a Server

To connect, you need the username of the account you want to log into and the Bluetooth MAC address of the server.

**From a Windows Client:**
```powershell
python bsh_client_windows.py username@00:11:22:33:44:55
```

**From a Linux Client:**
```bash
python3 bsh_client_linux.py username@00:11:22:33:44:55
```

If your server is running on a custom RFCOMM channel, append `-p <channel>`:

```bash
python3 bsh_client_linux.py username@00:11:22:33:44:55 -p 3
```

---

## Standalone Password Management

If you prefer not to use your native OS passwords for Bluetooth access, OpenBSH includes a standalone password database. These BSH-specific users must be mapped to an existing OS account to spawn a shell.

**Add a user (Linux):**
```bash
sudo python3 /opt/bsh/bsh_password.py adduser alice
```

**Add a user (Windows):**
```powershell
python bsh_password.py adduser alice
```

---

## License

*(This project does not currently contain a LICENSE file. See recommendations below.)*
