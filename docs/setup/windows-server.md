# Windows Server Setup

The OpenBSH Server on Windows is designed to run seamlessly as a background Windows Service. It hooks directly into the Windows security model to authenticate users and spawn restricted shell sessions.

## Prerequisites

Before installing the OpenBSH server, ensure that Bluetooth is turned on and discoverable on your Windows machine.

### Install Python
Ensure Python 3.8 or higher is installed and added to your system `PATH`.

### Install Dependencies
Open a Command Prompt or PowerShell terminal as **Administrator** and install the required Python packages. OpenBSH heavily relies on `pywin32` for service and system integration.

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
- Registers the python script as a Windows Service named `BSH Service` (Bluetooth Shell Service).
- Sets the service to start automatically on boot.
- The service will run under the `LocalSystem` account, which is required to impersonate logged-in users via `CreateProcessAsUser`.

> [!WARNING]
> Do **NOT** change the service user to a standard domain or local user account. The `LocalSystem` context holds the `SE_TCB_NAME` and `SE_ASSIGNPRIMARYTOKEN_NAME` privileges necessary for shell impersonation.

---

## Service Management

You can manage the service using the provided Python script, the Windows Services MMC snap-in (`services.msc`), or via standard Windows command-line tools.

### Using Python Command Line
```powershell
# Start the service
python bsh_service.py start

# Stop the service
python bsh_service.py stop

# Restart the service
python bsh_service.py restart
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

### The Standalone BSH Password DB (Optional)
If you wish to use passwords independent of the Windows system, you can use the built-in password database. Similar to the Linux version, these users will still need to be mapped to a legitimate Windows system user.

```powershell
python bsh_password.py adduser standalone_bsh_user
```

---

## File Locations & Logging

- **Logs Location:** `C:\ProgramData\BSH\logs\`
- **Configuration:** The default configuration file is `C:\ProgramData\BSH\config.json`, and runtime state is written under `C:\ProgramData\BSH`.

If you experience connection failures, always check the latest log file in `C:\ProgramData\BSH\logs\`.
