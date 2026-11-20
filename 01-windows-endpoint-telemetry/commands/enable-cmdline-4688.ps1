# Project 01 - Item 02: include command lines in Security Event 4688
# Run in Windows PowerShell as Administrator.
# Windows 10 Home has no Group Policy editor, so the policy's registry value is set directly.

# 1. Enable command-line capture in process-creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# 2. Controlled test: a process with a unique, searchable command line
cmd.exe /c echo cmdline-test

# 3. Verify: the marker only appears if the command line was captured
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-2)} |
  Where-Object Message -match 'cmdline-test' | Format-List TimeCreated, Message
# Pass: the process command line field shows: cmd.exe /c echo cmdline-test
# Nothing returned: reboot once (Restart-Computer) and repeat steps 2-3.

# Rollback (only if needed):
# reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f
