# Endpoint baseline (Item 01)

State of the Lenovo endpoint before and after the Project 01 changes. Raw outputs are in `commands/`.

| Area | Before (17–18 Nov) | After (18 Nov) | Evidence |
|---|---|---|---|
| OS | — | Windows 10 Home Single Language 22H2, build 19045.6456, 64-bit, es-ES | `commands/2026-11-18_project01_baseline.txt` |
| Defender | McAfee installed (Defender state not captured) | Active (Normal), real-time ON, tamper protection ON, signatures 18/11/2026 | `commands/2026-11-18_project01_baseline.txt` |
| Sysmon | v15.22, hash `B3B9EFA9…`, FileBlock rules blocking all executables | v15.22, hash `C20B9B98…`, FileBlock rules disabled (`include`) | `troubleshooting/2026-11-18_sysmon-self-block_before.txt` / `_after.txt` |
| Process Creation (4688) | No auditing | Success, with command lines | `commands/audit-policy-before.txt` / `-after.txt`, `screenshots/2026-11-18_project01_4688-cmdline.png` |
| Security Group Mgmt | Success | Success + Failure | `commands/audit-policy-before.txt` / `-after.txt` |
| User Account Mgmt | Success | Success + Failure | `commands/audit-policy-before.txt` / `-after.txt` |
| Logon / Logoff / Lockout / Special Logon | Already enabled (S+F / S / S / S) | Unchanged | `commands/audit-policy-before.txt` / `-after.txt` |
| Credential Validation (4776) | No auditing | Success + Failure (tested: 3 pairs of 4625 + 4776) | `screenshots/2026-11-18_project01_4776-4625-failed-logon.png` |
