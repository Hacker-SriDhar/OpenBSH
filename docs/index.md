# OpenBSH:  Bluetooth Shell

Welcome to the official documentation for **OpenBSH** — a robust, cross-platform Bluetooth Shell service. 

OpenBSH provides secure, SSH-style remote shell access over Bluetooth RFCOMM, enabling powerful out-of-band management for systems where network access is unavailable, restricted, or compromised.

## Why OpenBSH?

In many secure or edge environments, traditional IP networks (Wi-Fi, Ethernet) might be deliberately air-gapped, or a misconfiguration might lock administrators out. OpenBSH leverages Bluetooth to provide a reliable, proximity-based management channel.

### Key Features

- **Cross-Platform Support:** Fully functional server implementations for both **Windows** (as a Windows Service) and **Linux** (as a Systemd Daemon), along with cross-platform Python clients.
- **Enterprise-Grade Security:** All traffic is encrypted using **AES-256-GCM** with keys derived via PBKDF2 HMAC-SHA256. Secure authentication prevents unauthorized access.
- **SSH-Style PTY Experience:** Enjoy an interactive shell experience with pseudo-terminal (PTY) emulation, supporting standard shell utilities, command history, and continuous output.
- **Native OS Integration:** 
    - **Windows:** Integrates with `win32serviceutil`, uses `CreateProcessAsUser` for shell impersonation, and authenticates against Windows SAM.
    - **Linux:** Integrates with Systemd, uses `pty.openpty` for terminal emulation, and supports PAM authentication with `/etc/shadow` fallback.

## Documentation Structure

This site is structured to help you understand, deploy, and manage OpenBSH:

- **[Architecture](architecture.md):** Deep dive into how OpenBSH works under the hood.
- **Setup Guides:** Step-by-step instructions for deploying OpenBSH on [Linux](setup/linux-server.md), [Windows](setup/windows-server.md), and configuring [Clients](setup/client.md).
- **[Usage Guide](usage.md):** Learn how to connect, manage users, and troubleshoot common issues.
- **[Protocol & Security](protocol-security.md):** A detailed look at the custom BSH Wire Protocol and the cryptographic implementation.
