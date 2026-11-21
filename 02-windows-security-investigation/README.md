# Project 02 — Windows Security Event Investigation

I ran a controlled account and logon scenario on my own Windows 10 laptop and investigated it as a SOC case: I rebuilt the life of a temporary local admin account from creation to deletion in a single UTC timeline, using PowerShell and Splunk, and labelled every conclusion by how strongly the evidence supports it.

**Skills shown:** Windows Security auditing · event XML parsing in PowerShell · Splunk SPL · timeline building · failed-logon triage · MITRE ATT&CK mapping

## Results

| What I proved | Result |
|---|---|
| The SubStatus separates "wrong password" from "no such user" | `labuser` (exists): `0xC000006A` ×3 · `labfakeuser` (does not exist): `0xC0000064` ×5 |
| One command is not one event | `New-LocalUser` produced 5 events in the same second (4720, 4722, 4724, 4738 ×2) |
| One admin sign-in can produce two 4624s | Logon IDs `0x2b77670` and `0x2b776ea` link to each other: UAC split token |
| PowerShell and Splunk agree | 46 events, matching to the second after converting Splunk's Helsinki time to UTC |
| Name-based searches have a blind spot | Splunk missed 4732/4733 until I searched for the group: the member is recorded as a SID |
| No secret reached the logs | The password was typed at a `Read-Host` prompt; no 4688 command line contains it |

Full write-up: [`report.md`](report.md) · Timeline: [`timeline.md`](timeline.md)

## Scenario (UTC)

| When | Action | Events |
|---|---|---|
| 20 Nov 13:05 | Create `labuser`, add to Administrators | 4720, 4722, 4724, 4738, 4732 |
| 20 Nov 13:08–13:11 | Failed validations for `labfakeuser` (control) | 4648, 4776, 4625 |
| 21 Nov 10:35 | `runas /user:labuser cmd` with three wrong passwords | 4625, 4776 |
| 21 Nov 10:36 | `runas` with the correct password | 4776, 4648, 4672, 4624 ×2 |
| 21 Nov 10:36–11:10 | Remove from Administrators, delete account and profile | 4733, 4726 |

## Folder contents

```text
02-windows-security-investigation/
├── README.md
├── report.md                     # full 13-section report
├── timeline.md                   # UTC timeline with a label on every row
├── commands/
│   ├── scenario.ps1              # the scenario as run (no real passwords)
│   ├── query-auth-events.txt     # 4625 · 4624 · 4648 · 4672 · 4776
│   └── query-account-events.txt  # 4720 · 4722 · 4724 · 4738 · 4732 · 4733 · 4726
├── splunk/
│   └── searches.spl              # timeline search
└── screenshots/
```

## Screenshots

| File | Shows |
|---|---|
| `2026-11-20_project02_scenario-commands.png` | Session 2 PowerShell history: the evidence queries, group removal and account deletion |
| `2026-11-20_project02_4625-substatus.png` | Failed logons: `0xC0000064` for `labfakeuser`, `0xC000006A` for `labuser`, each with its 4776 |
| `2026-11-20_project02_4624-logontype.png` | The successful type 2 logon: two 4624 events whose logon IDs point at each other |
| `2026-11-20_project02_account-lifecycle.png` | Create, enable, change, add to and remove from Administrators (member shown as SID), delete |
| `2026-11-20_project02_splunk-timeline.png` | The same 46 events in Splunk (times shown in Helsinki time, UTC+2) |

## What I learned

An event ID only starts the question; the Status, SubStatus, logon type and linked logon IDs answer it. And because Windows records group members by SID, an investigation that searches only by account name can miss the most important event in the case: someone being made an administrator.

## Limitations

- One laptop, one test account, no real attack traffic.
- The two failed-logon tests used different logon types (3 and 2), so they compare "account exists or not", not logon methods.
- Two events are still Unknown (see report section 8), each with a next check.
- The raw Splunk export contains my account name and SIDs, so it is not published.
