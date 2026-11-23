# Project 04: controlled test that fires the alert "Failed logons: 3+ in 15 minutes"
# Run in a normal PowerShell. Target: labfakeuser (does not exist, so no real account can be locked out).
# Each attempt makes Windows log one failed logon (Event 4625).
1..4 | ForEach-Object {
  net use \\localhost\IPC$ /user:labfakeuser WrongPass-p04 2>&1 | Out-Null
  Start-Sleep -Seconds 2
}
Get-Date -Format "yyyy-MM-dd HH:mm:ss 'local'"
