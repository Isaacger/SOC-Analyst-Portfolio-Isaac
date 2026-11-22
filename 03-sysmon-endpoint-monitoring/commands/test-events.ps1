# Project 03: the four test events (run in a NORMAL, non-admin PowerShell)
cmd /c "whoami & echo p03-chain-test"                                    # Event 1: powershell > cmd > whoami
Test-NetConnection example.com -Port 443                                 # Event 3: network connection
Resolve-DnsName p03-dns-test.example.com -ErrorAction SilentlyContinue   # Event 22: DNS query (no record, still logged)
Set-Content "$env:USERPROFILE\Downloads\p03-test.ps1" "Write-Output p03" # Event 11: file created (overwrite behaviour unverified, see report section 6)
