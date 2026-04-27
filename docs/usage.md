# Usage Guide

Once OpenBSH is installed and running on a target server, managing users and connecting via the client is straightforward.

## Managing the Service

The OpenBSH daemon runs in the background. Depending on your operating system, you use different tools to verify its status.

=== "Linux (Systemd)"
    ```bash
    # View the status of the service
    systemctl status bsh

    # Follow the logs in real-time
    journalctl -u bsh -f
    ```

=== "Windows (Service MMC)"
    ```powershell
    # Check if the service is running
    Get-Service BSHService

    # Check logs
    Get-Content "C:\ProgramData\BSH\logs\bsh_service.log" -Wait
    ```

---

## Authentication Modes

OpenBSH supports two primary modes of authentication:

1. **Native OS Authentication (Default):**
    - On Windows, OpenBSH uses the `LogonUserW` API to verify the target Windows account password.
    - On Linux, OpenBSH uses PAM when available and falls back to `/etc/shadow`-based verification when running with sufficient privileges.

2. **Standalone BSH Database:**
    - OpenBSH ships with its own highly secure, standalone password database (`bsh_password.py`). 
    - This is useful if you want to grant BSH access using a *different* password than the system password, or if you want to strictly control which users can access the system via Bluetooth.
    - Standalone users *must* map to a valid OS user account, because OpenBSH needs a valid OS context to impersonate and spawn the shell.

---

## Managing Standalone Users

If you choose to use the Standalone Database, you manage users via the `bsh_password.py` utility.

> [!NOTE]
> On Linux, the utility is located at `/opt/bsh/bsh_password.py` and requires `sudo`. On Windows, it is located in your installation directory and requires an Administrator prompt.

### Add a New User
```bash
python bsh_password.py adduser johndoe
```
*This assumes that the OS account "johndoe" already exists.*

### Map to a Different OS User
If you want the BSH username to be different from the OS username:
```bash
python bsh_password.py adduser bsh_admin --system-user root
```
*When `bsh_admin` logs in, they will be dropped into a `root` shell.*

### Change a Password
```bash
python bsh_password.py passwd johndoe
```

### List Users
```bash
python bsh_password.py list
```

### Delete a User
```bash
python bsh_password.py deluser johndoe
```

---

## Connecting via the Client

The OpenBSH client provides an interactive, terminal-like experience.

### Basic Connection
To connect, pass the username and Bluetooth MAC address of the target server to your OS-specific client.

**From Windows:**
```powershell
python bsh_client_windows.py johndoe@00:11:22:33:44:55
```

**From Linux:**
```bash
python3 bsh_client_linux.py johndoe@00:11:22:33:44:55
```

### Custom Channels
Linux defaults to channel `1`, but the active RFCOMM channel may differ if you reconfigure it or if the platform assigns a different bound channel. If needed, specify the channel explicitly during connection:

**From Windows:**
```powershell
python bsh_client_windows.py johndoe@00:11:22:33:44:55 -p 4
```

**From Linux:**
```bash
python3 bsh_client_linux.py johndoe@00:11:22:33:44:55 -p 4
```

### Interactive Shell Experience
Once connected and authenticated, you are dropped into the server-side shell implementation (`cmd.exe` on the current Windows server, or the user's login shell on Linux).

The client will automatically handle:
- **Terminal Sizing:** When you resize your client terminal window, a `MSG_WINDOW_SIZE` packet is sent to the server. Linux servers apply it to the remote PTY; Windows servers currently accept the packet but do not apply a PTY resize.
- **Echo Suppression:** If connected to a Linux server, the client will suppress local keyboard echo, relying purely on the server's PTY, enabling complex terminal applications like `vim` or `htop`.
- **Keepalives:** The client sends background keepalive pings every 0.5s to ensure the Bluetooth link remains active and doesn't timeout during periods of inactivity.

To exit the session, simply type `exit` in the shell or press `Ctrl+C`.

### What Changes By Pair

The command you run is the same, but the interactive behavior depends strongly on both the client OS and the server OS.

| Pair | What You Will Notice |
|---|---|
| Windows client -> Windows server | The client uses local line editing, local echo, and local command history. The remote Windows shell is pipe-based, so terminal resizing is not applied remotely. |
| Windows client -> Linux server | The client behaves more like SSH. Local echo is disabled and the Linux PTY handles character echo, cursor movement, and full-screen applications. |
| Linux client -> Windows server | The client starts from Linux raw terminal mode but switches into a Windows-specific local editing path when the server reports `os = "Windows"`. Resize packets are still sent, but the Windows server does not apply them to a PTY. |
| Linux client -> Linux server | This is the most complete PTY path. The Linux client forwards keystrokes character-by-character, and the remote PTY handles echo, editing, and terminal resizes. |

### Important Protocol Caveat

Both Linux and Windows servers currently advertise `features = ["pty", "signals", "password"]` in `MSG_HELLO`. On Linux, that matches the actual PTY-backed session. On Windows, the shell is still pipe-based and `MSG_WINDOW_SIZE` is ignored, so the `os` field is a better predictor of session behavior than the `pty` feature flag.
