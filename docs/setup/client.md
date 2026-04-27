# Client Setup

The OpenBSH Client is a Python-based utility that allows you to connect to an OpenBSH server over Bluetooth RFCOMM. 

Because the heavy lifting (PTY emulation, service management, user impersonation) is handled entirely by the server, the client is relatively lightweight and highly cross-platform.

## Prerequisites

The client requires a Python 3 environment and a Bluetooth adapter. It runs natively on both Windows and Linux.

### Install Dependencies

Whether you are on Windows or Linux, install the `cryptography` package via `pip`. On Linux, the client uses the Python standard library Bluetooth socket support for RFCOMM connections. `PyBluez` is optional and only helps with SDP-based channel discovery.

=== "Windows"
    ```powershell
    pip install cryptography
    ```

=== "Linux"
    ```bash
    sudo apt install libbluetooth-dev
    pip3 install cryptography
    ```

---

## Installation

There is no formal installation process for the client. The client is a standalone set of Python files designed to be run portably.

1. Clone or download the OpenBSH repository.
2. Navigate to the `Client/` directory.

### Project Structure
```text
Client/
├── bsh_client.py           # Shared client implementation
├── bsh_client_windows.py   # Windows-specific client logic
├── bsh_client_linux.py     # Linux-specific client logic
├── bsh_protocol.py         # The shared wire protocol
└── bsh_crypto.py           # The shared cryptography library
```

---

## Basic Usage

To connect to a server, you only need the target username and the Bluetooth MAC Address of the target machine. Ensure you are running the specific client script for your Operating System: `bsh_client_windows.py` for Windows, or `bsh_client_linux.py` for Linux.

### Finding the Server MAC Address

If you don't know the MAC address of the target server, pairing the devices through the OS Bluetooth settings is usually the most reliable path. Command-line tools can also help, depending on platform support.

**On the Server (Linux):**
```bash
hciconfig -a
# Look for "BD Address: XX:XX:XX:XX:XX:XX"
```

**On the Server (Windows):**
```powershell
Get-PnpDevice -Class Bluetooth
# Then inspect the adapter in Device Manager or Windows Bluetooth settings
```

### Connecting to the Server

Once you have the MAC address, use the OS-specific client script to connect:

**From Windows:**
```powershell
python bsh_client_windows.py user@00:11:22:33:44:55
```

**From Linux:**
```bash
python3 bsh_client_linux.py user@00:11:22:33:44:55
```

If the server is running on a non-standard RFCOMM channel (the default is channel `1`), you can specify it manually:

**From Windows:**
```powershell
python bsh_client_windows.py user@00:11:22:33:44:55 -p 3
```

**From Linux:**
```bash
python3 bsh_client_linux.py user@00:11:22:33:44:55 -p 3
```

> [!TIP]
> The OpenBSH client provides a highly responsive PTY experience. If connecting to a Linux server, the client will automatically disable local terminal echo, relying entirely on the server's PTY to render keystrokes, ensuring that programs like `vim`, `nano`, and `htop` work flawlessly.

---

## Pair-Specific Client Behavior

The same client binary can connect to both server platforms, but it does not behave identically in all four pairings.

### Windows Client

- **To Linux server:**
  The client uses the remote Linux PTY as the source of truth for echo and line editing. Local echo is disabled, arrow keys and control sequences are forwarded, and `MSG_WINDOW_SIZE` changes are applied by the server.
- **To Windows server:**
  The client enables a local line editor with local echo and history because the remote Windows shell is pipe-based rather than PTY-based. `MSG_WINDOW_SIZE` packets are still sent, but the server ignores them.

### Linux Client

- **To Linux server:**
  The client stays in raw terminal pass-through mode. Keystrokes are forwarded character-by-character and the Linux PTY handles canonical editing, full-screen apps, and resize events.
- **To Windows server:**
  The client still uses Linux raw terminal mode underneath, but it switches into a Windows-specific local editing path once the server reports `os = "Windows"`. Resize packets continue to be emitted, but the Windows server accepts them without applying a PTY resize.

### RFCOMM Discovery Differences

- **Windows client:**
  Uses Windows SDP lookup first, then RFCOMM channel scan, then manual entry.
- **Linux client:**
  Uses PyBluez SDP lookup when available, then `sdptool`, then RFCOMM channel scan, then manual entry.

### Hello/Feature Caveat

Both server implementations currently advertise `features = ["pty", "signals", "password"]` during `MSG_HELLO`. That is accurate for the Linux server, but only partially accurate for the Windows server. In practice, clients should treat the remote `os` value as the main indicator of whether the session is PTY-backed.
