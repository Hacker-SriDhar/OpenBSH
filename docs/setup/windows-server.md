# Windows Server Setup

The OpenBSH Server on Windows is designed to run as a background Windows Service. It hooks directly into the Windows security model to authenticate users and spawn restricted shell sessions.

## Prerequisites

Before installing the OpenBSH server, ensure that Bluetooth is turned on and discoverable on your Windows machine.

### Install Python
Ensure Python 3.8 or higher is installed and added to your system `PATH`.

### Install Dependencies
Open a Command Prompt or PowerShell terminal as **Administrator** and install the required Python packages. OpenBSH relies on `pywin32` for service and system integration.

```powershell
pip install pywin32 cryptography
```

---

## Installation

The Windows server relies on `win32serviceutil` to register itself as a native Windows service.

1. Download or clone the OpenBSH repository.
2. Navigate to the `windows/` directory.
3. Open an **Administrator** command prompt.
4. Run the installation command:

```powershell
python bsh_service.py install
```

### What the installation does:
- Registers the Python script as a Windows Service named `BSH Service` (Bluetooth Shell Service).
- Sets the service to start automatically on boot.
- Runs the service under the `LocalSystem` account, which is required to impersonate logged-in users via `CreateProcessAsUser`.

> [!WARNING]
> Do **NOT** change the service user to a standard domain or local user account. The `LocalSystem` context holds the `SE_TCB_NAME` and `SE_ASSIGNPRIMARYTOKEN_NAME` privileges necessary for shell impersonation.

---

## Service Management

You can manage the service using the provided Python script, the Windows Services MMC snap-in (`services.msc`), or standard Windows command-line tools.

### Using Python Command Line
```powershell
# Install (or reinstall) the service
python bsh_service.py install

# Update (alias for install - re-registers the service)
python bsh_service.py update

# Start the service
python bsh_service.py start

# Stop the service
python bsh_service.py stop

# Restart the service
python bsh_service.py restart

# View status and recent logs
python bsh_service.py status

# View logs (tail style)
python bsh_service.py logs
python bsh_service.py logs --follow
```

### Using Windows Built-ins
```powershell
# Start
net start BSHService

# Stop
net stop BSHService
```

---

## User Authentication

On Windows, OpenBSH uses `LogonUserW` to validate the supplied credentials for the target Windows account.

**You do not need to create standalone BSH users.** Any user who can log into the Windows machine locally can authenticate over BSH.

To connect from a client, simply use your Windows username and password.

In practice, the current client flow is simplest when the username matches the Windows account name expected by the server configuration.

### Standalone BSH Password Database *(planned - not yet available)*

A future release of OpenBSH may include an optional standalone password database that allows BSH credentials independent of Windows account passwords. Until then, use native Windows account credentials to authenticate.

---

## File Locations & Logging

- **Logs Location:** `C:\ProgramData\BSH\logs\`
- **Configuration:** The default configuration file is `C:\ProgramData\BSH\config.json`, and runtime state is written under `C:\ProgramData\BSH`.

The Windows service creates the following configuration keys by default:

| Key | Default | Description |
|---|---|---|
| `channel` | `1` | Preferred RFCOMM channel for the service-managed server. |
| `log_level` | `DEBUG` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `log_file` | `C:\ProgramData\BSH\logs\bsh_service.log` | Path to the primary service log file. |

When `windows/bsh_server_service.py` is run directly instead of through the service wrapper, it starts with `channel=0`, which maps to `BT_PORT_ANY` and lets Windows assign the RFCOMM channel dynamically.

If you experience connection failures, always check the latest log file in `C:\ProgramData\BSH\logs\`.
