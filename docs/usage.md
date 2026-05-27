# Usage Guide

Once OpenBSH is installed and running on a target server, managing users and connecting via the client is straightforward.

## Managing the Service

The OpenBSH daemon runs in the background. Depending on your operating system, you use different tools to verify its status.

=== "Linux (Systemd)"
    ```bash
    # View the status of the service
    systemctl status bsh

    # Follow the logs in real-time (systemd journal)
    journalctl -u bsh -f

    # Alternative: Python log viewer (no sudo needed)
    python3 /opt/bsh/bsh_service.py logs             # last 50 lines
    python3 /opt/bsh/bsh_service.py logs --follow    # tail -f style
    python3 /opt/bsh/bsh_service.py logs -n 100      # last 100 lines
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

OpenBSH supports two documentation-level modes of authentication:

1. **Native OS Authentication (Default):**
    - On Windows, OpenBSH uses the `LogonUserW` API to verify the target Windows account password.
    - On Linux, OpenBSH uses PAM when available and falls back to `/etc/shadow`-based verification when running with sufficient privileges.

2. **Standalone BSH Password Database** *(not available in this release):*
    - The current release does not ship a standalone BSH password database or `bsh_password.py` helper.
    - Authentication is performed against native OS accounts only.
    - Any future standalone credential store would still need to map to a valid OS user account so that OpenBSH can impersonate and spawn the shell.

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
- **Keepalives:** The client wakes its background sender loop every 0.5 seconds, but it only emits an actual keepalive packet roughly every 5 seconds to keep the Bluetooth link active during idle periods.

To exit the session, simply type `exit` in the shell or press `Ctrl+C`.

### Dynamic Adaptation By Pair

The command you run is the same, but the interactive behavior depends strongly on the dynamic adaptation between the client OS and the server OS. The clients automatically adjust their input model based on the server's backend shell.

| Pair | What You Will Notice |
|---|---|
| Windows client -> Windows server | The client uses local line editing, local echo, and local command history. The remote Windows shell is pipe-based, so terminal resizing is not applied remotely. |
| Windows client -> Linux server | The client behaves more like SSH. Local echo is disabled and the Linux PTY handles character echo, cursor movement, and full-screen applications. |
| Linux client -> Windows server | The client starts from Linux raw terminal mode but switches into a Windows-specific local editing path when the server reports `os = "Windows"`. Resize packets are still sent, but the Windows server does not apply them to a PTY. |
| Linux client -> Linux server | This is the most complete PTY path. The Linux client forwards keystrokes character-by-character, and the remote PTY handles echo, editing, and terminal resizes. |

### Important Protocol Caveat

Both Linux and Windows servers currently advertise `features = ["pty", "signals", "password"]` in `MSG_HELLO`. On Linux, that matches the actual PTY-backed session. On Windows, the shell is still pipe-based and `MSG_WINDOW_SIZE` is ignored, so the `os` field is a better predictor of session behavior than the `pty` feature flag.
