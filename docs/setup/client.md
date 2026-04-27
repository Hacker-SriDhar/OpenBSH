# Client Setup

The OpenBSH Client is a Python-based utility that allows you to connect to an OpenBSH server over Bluetooth RFCOMM. 

Because the heavy lifting (PTY emulation, service management, user impersonation) is handled entirely by the server, the client is relatively lightweight and highly cross-platform.

## Prerequisites

The client requires a Python 3 environment and a Bluetooth adapter. It runs natively on both Windows and Linux.

### Install Dependencies

Whether you are on Windows or Linux, install the `cryptography` package via `pip`. If you are on Linux, you will also need the `PyBluez` package to discover and bind to RFCOMM sockets.

=== "Windows"
    ```powershell
    pip install cryptography
    ```

=== "Linux"
    ```bash
    sudo apt install libbluetooth-dev
    pip3 install cryptography PyBluez
    ```

---

## Installation

There is no formal installation process for the client. The client is a standalone set of Python files designed to be run portably.

1. Clone or download the OpenBSH repository.
2. Navigate to the `Client/` directory.

### Project Structure
```text
Client/
├── bsh_client.py           # The universal entry point
├── bsh_client_windows.py   # Windows-specific client logic
├── bsh_client_linux.py     # Linux-specific client logic
├── bsh_protocol.py         # The shared wire protocol
└── bsh_crypto.py           # The shared cryptography library
```

---

## Basic Usage

To connect to a server, you only need the target username and the Bluetooth MAC Address of the target machine. Ensure you are running the specific client script for your Operating System: `bsh_client_windows.py` for Windows, or `bsh_client_linux.py` for Linux.

### Finding the Server MAC Address

If you don't know the MAC address of the target server, you can pair the devices natively using your OS's Bluetooth manager, or use command-line discovery tools.

**On the Server (Linux):**
```bash
hciconfig -a
# Look for "BD Address: XX:XX:XX:XX:XX:XX"
```

**On the Server (Windows):**
```powershell
ipconfig /all
# Look for the "Bluetooth Network Connection" Physical Address
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
