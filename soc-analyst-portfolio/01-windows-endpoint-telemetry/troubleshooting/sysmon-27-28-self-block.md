# Troubleshooting: Sysmon configuration silently blocking executables (Events 27/28)

**Project:** 01 – Windows Endpoint Telemetry and SIEM Integration
**Date:** 2026-11-18
**Endpoint:** Windows 10 Home Single Language 22H2 (build 19045), Sysmon v15.22
**Status:** Resolved and verified

---

## 1. Symptom

Sysinternals tools (Process Monitor, Process Explorer) could not be downloaded, extracted or copied onto the endpoint. No error appeared in the console or in Explorer: the files simply did not arrive. The initial assumption was that "Windows was blocking Sysinternals".

## 2. Environment and first observations

- Sysmon service `Sysmon64` was running and the `Microsoft-Windows-Sysmon/Operational` log was receiving events, so Sysmon itself was healthy.
- `sysmon64 -c` showed every rule type configured as `onmatch: exclude` with no rules, including the two blocking event types:

```text
- FileBlockExecutable   onmatch: exclude
- FileBlockShredding    onmatch: exclude
```

## 3. Hypothesis

In Sysmon, an empty `exclude` block means *nothing is excluded, so everything matches*. For logging event types this only produces noise. For `FileBlockExecutable` (Event 27) and `FileBlockShredding` (Event 28) a match means **block**, so this configuration would block every executable written to disk and every file-shredding attempt.

Alternative explanation considered: Microsoft Defender. A Defender block would appear as Event 1116/1117 in `Microsoft-Windows-Windows Defender/Operational`; a Sysmon block appears as Event 27/28 in the Sysmon log. Checking which log holds the event attributes the block to the right control.

## 4. Reproduction (controlled, harmless)

A signed Windows binary was copied to a lab folder:

```powershell
Copy-Item C:\Windows\System32\notepad.exe C:\LabEvidence\blocktest.exe
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=27,28} -MaxEvents 5 | Format-List TimeCreated, Id, Message
```

Result:
- The copy produced **no console error**.
- Sysmon logged **Event 27 – File Block Executable** in the same second: `Image: powershell.exe`, `TargetFilename: C:\LabEvidence\blocktest.exe`.
- Sysmon was also logging **Event 28 – File Block Shredding** every minute: `svchost.exe` (Local Service) blocked from deleting `C:\Windows\System32\sru\SRU.log`, i.e. normal Windows resource-usage (SRUM) maintenance was being blocked.

Full sanitised output: `2026-11-18_sysmon-self-block_before.txt`.

## 5. Root cause

The Sysmon configuration (`sysmon-all.xml`, hash `B3B9EFA9…`) enabled `FileBlockExecutable` and `FileBlockShredding` with empty `exclude` rule sets. A monitoring configuration had unintentionally become an application-control policy that blocked all executable writes, silently.

## 6. Fix (one change)

1. Copied the configuration to `sysmon-lab.xml`.
2. Changed only the two blocking elements from `onmatch="exclude"` to `onmatch="include"` (an empty include matches nothing, so nothing is blocked).
3. Applied it with `sysmon64 -c C:\LabEvidence\sysmon-lab.xml`.

Rollback: re-apply the original `sysmon-all.xml` with `sysmon64 -c`.

## 7. Verification

| Check | Before | After |
|---|---|---|
| FileBlockExecutable / FileBlockShredding | `exclude` (block all) | `include` (block none) |
| Active config hash | `B3B9EFA9…` | `C20B9B98…` |
| Copy test (`notepad.exe` → `blocktest.exe`) | Silently blocked, Event 27 | 200,704 bytes written |
| Event 27/28 since the fix | Every minute | 0 |
| After reboot (baseline at 14:30) | — | Hash and `include` rules unchanged |

Process Explorer was then installed and ran normally. Full output: `2026-11-18_sysmon-self-block_after.txt`.

## 8. Triage classification of the Event 28 alerts

**Benign true positive.** The rule fired exactly as configured and the activity was real, but it was legitimate Windows maintenance (built-in service account, non-executable log file). The correct response was to tune the rule, not to escalate.

## 9. What went wrong in the process (honest notes)

- The registry backup of the Sysmon configuration was taken **after** the first apply, so it holds the fixed configuration. The original file remains available for rollback. In proper change management the backup comes first.
- An unnecessary schema check was run even though the Event 27/28 entries already proved that this Sysmon version supported the blocking events. Lesson: check existing evidence before running new checks.

## 10. Prevention

- Never deploy a "log everything" Sysmon template without reviewing the blocking event types (27, 28) separately.
- After any Sysmon configuration change: record the config hash, confirm with `sysmon64 -c`, and run a harmless copy test.
- Treat Event 27/28 as high-signal: an unexpected block event means either an attack was stopped or the configuration is wrong. Both need attention.

## 11. Interview summary (30 seconds)

> Tools were silently failing to install on my endpoint. I reproduced it with a benign file copy and correlated the failure to a Sysmon Event 27 in the same second. The root cause was an empty exclude rule on a blocking event type, which turned my monitoring config into an accidental application-control policy. I changed that one setting, verified the new config hash, repeated the test, and confirmed zero new block events afterwards.
