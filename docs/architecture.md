# System Architecture

OpenBSH is designed with a robust, cross-platform architecture that cleanly separates the core wire protocol and cryptography from platform-specific system integration (like pseudo-terminals and service management).

## High-Level Component View

At its core, OpenBSH consists of a **Client**, a **Server**, and a shared **Protocol Layer**.

```mermaid
graph TD
    subgraph Client System
        C[BSH Client]
        CryptoC[bsh_crypto.py]
        ProtoC[bsh_protocol.py]
        C --- CryptoC
        C --- ProtoC
    end

    subgraph RFCOMM Bluetooth Link
        BT((Bluetooth RFCOMM\nPost-auth AES-256-GCM))
    end

    subgraph Server System
        S[BSH Server Daemon/Service]
        CryptoS[bsh_crypto.py]
        ProtoS[bsh_protocol.py]
        Auth[Auth Module: PAM / Win32]
        PTY[Shell / PTY Emulation]
        
        S --- CryptoS
        S --- ProtoS
        S --- Auth
        S --- PTY
    end

    C <==> BT
    BT <==> S
```

---

## Core Modules

OpenBSH relies on several key Python modules. To ensure maximum compatibility between Windows and Linux, the cryptographic and protocol logic is completely identical across platforms.

### 1. `bsh_protocol.py` (The Wire Protocol)
This file defines the strict packet structure used to communicate over Bluetooth. Because Bluetooth RFCOMM provides a reliable stream (similar to TCP), `bsh_protocol.py` handles framing: defining the Start of Frame (`0xAA`), message types (e.g., `MSG_HELLO`, `MSG_DATA_IN`), payloads, and checksum validation.

### 2. `bsh_crypto.py` (The Security Layer)
Once the server and client mutually authenticate, `bsh_crypto.py` is engaged. It implements **AES-256-GCM** encryption. All subsequent shell traffic is encrypted and authenticated. The GCM (Galois/Counter Mode) tag ensures that any tampering with the packet over the air is instantly detected and the connection is dropped.

### 3. Platform-Specific Server Logic
While the protocol is identical, interacting with the operating system requires highly tailored code.

#### **Windows Service (`bsh_server_service.py` & `bsh_service.py`)**
- **Service Management:** Uses `win32serviceutil` to run seamlessly in the background as a native Windows service.
- **Authentication:** Uses Windows `LogonUserW` (via `ctypes`) to validate credentials for the target Windows account.
- **Impersonation:** Uses Windows token-based process creation to spawn the current pipe-based `cmd.exe` shell under the authenticated user's context.

#### **Linux Daemon (`bsh_server_service.py` & `bsh_service.py`)**
- **Service Management:** Wrapped in a native `systemd` unit (`bsh.service`).
- **Authentication:** Uses the `python-pam` library to authenticate against PAM (Pluggable Authentication Modules). If PAM fails or isn't present, it falls back to parsing `/etc/shadow`.
- **Terminal Emulation:** Uses `pty.openpty()` to create a proper pseudo-terminal, then calls `os.fork()` and `os.execv()` (along with `setuid`/`setgid`) to drop root privileges and run the user's default shell (e.g., `/bin/bash`).

---

## Authentication Mechanism

OpenBSH performs a two-step password authentication exchange followed by session key establishment.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>S: MSG_HELLO (Client Info)
    S->>C: MSG_HELLO (Server Info, Auth Methods)
    
    C->>S: MSG_AUTH_PASSWORD_REQUEST (Username)
    S->>C: MSG_AUTH_PASSWORD_CHALLENGE (32-byte Challenge)
    C->>S: MSG_AUTH_PASSWORD_RESPONSE (JSON payload with password)
    
    Note over S: Server verifies the password against<br/>the BSH password DB or native OS auth
    
    S->>C: MSG_AUTH_SUCCESS (Session Key)
    
    Note over C, S: Connection switches to AES-256-GCM
    C->>S: MSG_DATA_IN (Encrypted)
    S->>C: MSG_DATA_OUT (Encrypted)
```

1. **Hello Exchange:** Both sides advertise their version and OS capabilities. This is critical for clients to adjust their terminal emulation (e.g., disabling local echo if the server is Linux).
2. **Password Exchange:** The server sends a random challenge, then expects `MSG_AUTH_PASSWORD_RESPONSE`. In the current client implementation, that response carries the plaintext password inside the BSH packet payload.
3. **Session Key Negotiation:** If authentication succeeds, the server generates a random AES-256 session key and sends it to the client. From this moment, subsequent packet payloads are encrypted.

---

## Cross-Platform Pair Matrix

OpenBSH uses one shared packet protocol, but the runtime behavior is not identical across all client/server pairings. The most important differences are in RFCOMM discovery, terminal editing, and whether `MSG_WINDOW_SIZE` changes an actual PTY.

| Pair | RFCOMM Discovery Path | Server `os` Value | Actual Shell Backend | Editing Authority | Resize Handling |
|---|---|---|---|---|---|
| Windows client -> Windows server | Windows SDP -> channel scan -> manual | `Windows` | `cmd.exe` with pipes | Client-side line editor | Ignored by server |
| Windows client -> Linux server | Windows SDP -> channel scan -> manual | `Linux` | PTY-backed login shell | Remote Linux PTY | Applied to PTY |
| Linux client -> Windows server | PyBluez SDP -> `sdptool` -> scan -> manual | `Windows` | `cmd.exe` with pipes | Linux client uses Windows-specific local editing path | Ignored by server |
| Linux client -> Linux server | PyBluez SDP -> `sdptool` -> scan -> manual | `Linux` | PTY-backed login shell | Remote Linux PTY | Applied to PTY |

### Design Notes

- Both servers currently advertise `features = ["pty", "signals", "password"]` in `MSG_HELLO`.
- On Linux this matches reality because the session is backed by `pty.openpty()`.
- On Windows this is only partially true:
  `MSG_INTERRUPT` is supported, but the shell is pipe-based and `MSG_WINDOW_SIZE` is accepted without changing a real terminal.
- Clients therefore key most of their interactive behavior off the remote `os` field rather than treating the `pty` feature flag as authoritative.
