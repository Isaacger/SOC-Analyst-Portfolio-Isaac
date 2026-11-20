# Project 01 - Endpoint baseline (read-only)
# Run in Windows PowerShell as Administrator.
# Note: sysmon64 writes UTF-16 to stderr, so its section shows spaced letters and a
# cosmetic NativeCommandError in PowerShell 5.1. Use a screenshot of `sysmon64 -c` for the report.

$out = "C:\LabEvidence\$(Get-Date -Format yyyy-MM-dd)_project01_baseline.txt"
& {
  "=== OS ==="
  $os = Get-CimInstance Win32_OperatingSystem
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  [pscustomobject]@{ Edition=$os.Caption; Version=$cv.DisplayVersion; Build="$($os.BuildNumber).$($cv.UBR)"
    Arch=$os.OSArchitecture; UILang=(Get-UICulture).Name } | Format-List
  "=== Disk C ==="
  Get-Volume -DriveLetter C | Select-Object @{n='Size_GB';e={[math]::Round($_.Size/1GB,1)}},@{n='Free_GB';e={[math]::Round($_.SizeRemaining/1GB,1)}} | Format-List
  "=== Defender ==="
  Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated | Format-List
  "=== Sysmon ==="
  Get-Service Sysmon64 | Format-List Name,Status,StartType
  sysmon64 -c 2>&1
  "=== Audit policy (current) ==="
  auditpol /get /category:*
} *>&1 | Out-File $out -Encoding utf8
notepad $out
