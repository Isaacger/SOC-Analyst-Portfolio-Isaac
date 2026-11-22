# Project 03: apply the curated config and verify it (run as admin)
sysmon64 -c                                                              # current hash (before: C20B9B98...)
Copy-Item C:\LabEvidence\sysmon-lab.xml C:\LabEvidence\sysmon-lab-BEFORE.xml   # rollback file
Get-FileHash C:\LabEvidence\sysmon-lab.xml, C:\LabEvidence\sysmon-lab-BEFORE.xml | Format-Table Hash, Path   # both must match
sysmon64 -c C:\LabEvidence\sysmon-p03.xml                                # apply
sysmon64 -c                                                              # verify: new hash 196066F4...
# Rollback if anything breaks:
# sysmon64 -c C:\LabEvidence\sysmon-lab-BEFORE.xml
