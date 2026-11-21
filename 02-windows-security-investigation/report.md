# Project 02 Report: Windows Security Event Investigation

**Author:** Isaac · **Dates:** 20–21 November 2026 · **Status:** Complete

---

## 1. Overview

I ran a controlled account-management and logon scenario on my own Windows 10 laptop, then investigated the resulting Security events as a SOC analyst would. I reconstructed the life of a temporary local account (`labuser`) from creation to deletion, compared failed logons against an account that exists and one that does not, explained a two-event administrator logon, and separated what the events prove from what I can only interpret.

## 2. Objectives

1. Generate account-management and authentication events through a controlled, documented scenario.
2. Explain each event from my own data: 4720, 4722, 4724, 4738, 4732, 4733, 4726, 4625, 4776, 4648, 4672, 4624.
3. Build a single UTC timeline from PowerShell and Splunk and show the two sources agree.
4. Answer one investigation question: does the 4625 SubStatus tell a forgotten password apart from guessing?
5. Label every conclusion as Observed, Interpretation, Hypothesis, Confirmed or Unknown.

## 3. Scope and Authorisation

- **In scope:** my own Lenovo laptop and a temporary local account, `labuser`, created for this test. A second name, `labfakeuser`, was used for failed logons and never existed.
- **Safety rules I followed:**
  - No password on any command line. Event 4688 records command lines and forwards them to Splunk, so the `labuser` password was entered through a `Read-Host -AsSecureString` prompt.
  - The Administrators group was addressed by its well-known SID, `S-1-5-32-544`, because the group is called *Administradores* on my Spanish Windows.
  - The wrong passwords were made-up test strings.
- **Not in scope:** other accounts, other machines, remote logons.

## 4. Lab Environment

| Component | Details |
|---|---|
| Endpoint | Lenovo IdeaPad 320, Windows 10 Home Single Language 22H2, build 19045, Spanish (es-ES) |
| Auditing | Credential Validation (S+F), Logon (S+F), Account Management (S+F), Special Logon (S), Process Creation with command lines |
| Local investigation | PowerShell `Get-WinEvent` reading event XML (field names are English on any Windows language) |
| SIEM | Splunk Cloud trial, index `main`, Splunk Universal Forwarder (Security + Sysmon logs) |
| Time | Laptop on Europe/Helsinki (UTC+2); everything in this report is UTC |

On 20 November my first Splunk Cloud account went into account recovery, which Splunk said would take a few days. To keep working, I started a second trial and reinstalled the forwarder credentials package. The new trial contains the 20 November scenario events (see the Splunk timeline screenshot). *Interpretation:* the forwarder re-sent the existing Security log after reconfiguration, because `inputs.conf` uses `start_from = oldest`.

## 5. Scenario and Hypothesis

The scenario ran in two sessions. Full commands: `commands/scenario.ps1`.

| Session | UTC | Action | Expected events |
|---|---|---|---|
| 1 (20 Nov) | 13:05:15 | Create `labuser` | 4720, 4722, 4724, 4738 |
| 1 | 13:05:43 | Add to Administrators | 4732 |
| 1 | 13:08–13:11 | Control test: failed validations for `labfakeuser` (does not exist) | 4648, 4776, 4625 |
| 1 | 13:12:54 | Remove from Administrators | 4733 |
| 2 (21 Nov) | 10:34:34 | Add to Administrators again | 4732 |
| 2 | 10:35:03 – 10:35:26 | `runas /user:labuser cmd`, three wrong passwords | 4625, 4776 |
| 2 | 10:36:02 | `runas` with the correct password, `whoami`, `exit` | 4776, 4648, 4672, 4624 |
| 2 | 10:36:36 | Remove from Administrators | 4733 |
| 2 | 11:10:58 | Delete `labuser`, then its profile folder | 4726 |

**Investigation question:** what SubStatus does 4625 record for a wrong password on an account that exists, compared with an account that does not, and what does the difference tell a SOC analyst?

**Prediction:** both would share the general Status `0xC000006D` (logon failure), but the SubStatus would differ: "user does not exist" for `labfakeuser` and "wrong password" for `labuser`.

## 6. Methodology

1. **Collection with PowerShell.** Two XML-based queries, one per question:
   - `commands/query-auth-events.txt`: 4625, 4624, 4648, 4672, 4776 for `labuser` and `labfakeuser`, with logon type, Status, SubStatus, logon ID, linked logon ID and process.
   - `commands/query-account-events.txt`: 4720, 4722, 4724, 4738, 4732, 4733, 4726, with subject, target and member SID.
2. **Cross-check in Splunk.** `splunk/searches.spl` returned 46 events for the scenario. Splunk displayed Helsinki time; converted to UTC, every event matched the PowerShell output to the second (for example 4726 at 11:10:58 UTC and the 4624 pair at 10:36:02 UTC).
3. **Search correction.** My first Splunk search used only the text `labuser` and missed 4732 and 4733, because group-membership events record the member as a **SID**, not a name. I added a clause for those event codes on the Administrators group.
4. **Timeline.** Merged both sources into `timeline.md`, with a label on every row.

## 7. Evidence and Results

### Failed logons: the SubStatus comparison

| Account | Exists? | Logon type | Status | SubStatus | Meaning |
|---|---|---|---|---|---|
| `labfakeuser` | No | 3 (network, NTLM) | `0xC000006D` | `0xC0000064` | User name does not exist |
| `labuser` | Yes | 2 (interactive, `runas`) | `0xC000006D` | `0xC000006A` | User exists, password wrong |

**Observed:** five `labfakeuser` failures and three `labuser` failures, each paired with a 4776 in the same second (`2026-11-20_project02_4625-substatus.png`). The prediction was correct.

**Caveat:** the two tests also differ in method. `labfakeuser` was tested with `PrincipalContext.ValidateCredentials`, which produces a type 3 network logon over NTLM; `labuser` was tested with `runas`, a type 2 interactive logon. The SubStatus comparison is valid for "account exists or not", but not for comparing logon types.

### The successful administrator logon (21 Nov, 10:36:02 UTC)

| Event | What it showed |
|---|---|
| 4776 | Credential validation succeeded (`0x0`) |
| 4648 | My account requested a logon with explicit credentials for `labuser` (what `runas` does) |
| 4672 | Special privileges assigned to the new logon, including `SeDebugPrivilege`, `SeBackupPrivilege` and `SeTakeOwnershipPrivilege` |
| 4624 ×2 | Two type 2 logons for `labuser`, logon IDs `0x2b77670` and `0x2b776ea`, each listing the other as its linked logon ID (`2026-11-20_project02_4624-logontype.png`) |

**Interpretation:** the pair is UAC's split token. Because `labuser` was an administrator, Windows created a full (elevated) token and a filtered (limited) token for the same sign-in and linked them. The linked logon IDs are observed; the "elevated: yes / no" difference is what makes the split-token reading specific.

### Account lifecycle

`2026-11-20_project02_account-lifecycle.png` shows one `New-LocalUser` command producing five events in the same second: 4720 (created), 4722 (enabled), 4738 twice (attributes changed) and 4724 (password set). Windows records an account creation as several operations, so **one command is not one event**. The 4732 and 4733 events show the member only as a SID.

### Other events found

- **4688:** `runas.exe` four times (three wrong passwords, one correct) and `cmd.exe` and `conhost.exe` under `labuser`. No command line contains a password.
- **4634 ×2 (10:37:22):** both linked sessions ended after `exit`.
- **4798 (20 Nov 14:00:43, 21 Nov 10:22:06):** `LogonUI.exe` read the local group membership of `labuser`.

## 8. Analysis and Findings

| # | Finding | Label |
|---|---|---|
| 1 | `labuser` was created, added to Administrators, failed three logons, logged on successfully, was removed from Administrators and was deleted, in that order | **Confirmed** (two independent sources agree: PowerShell and Splunk) |
| 2 | A wrong password on an existing account gives SubStatus `0xC000006A`; an unknown user name gives `0xC0000064` | **Observed** |
| 3 | The two 4624 events are one administrator sign-in split into a full and a limited token | **Interpretation** (supported by linked logon IDs) |
| 4 | The `cmd.exe` started by `runas` ran with the limited token | **Interpretation** (UAC default for `runas`; not shown in a screenshot) |
| 5 | `LogonUI.exe` read `labuser`'s groups because the sign-in screen lists local accounts | **Hypothesis**: both 4798 events fall near my own sign-ins, which I have not yet checked against 4624 |
| 6 | Two of the five `labfakeuser` failures (20 Nov 13:08:13, eight seconds before my three-password loop, and 13:11:43) are not in my session history | **Unknown**. Next check: the persistent PowerShell history file, `(Get-PSReadLineOption).HistorySavePath` |
| 7 | Four 4738 events on **my own** account, made by the machine account, 21 Nov 10:21–10:28 | **Unknown**. *Hypothesis to test:* they coincide with my sign-in that morning (Microsoft account sign-in updating the local account); check 4624 for my account at 10:21 |

### False positives: a forgotten password vs password guessing

A count of 4625 events does not prove an attack. In Project 01, four of seven failed logons were benign: browser password checks by Edge and Chrome, a Guest account lookup and a lock-screen failure. The SubStatus adds a dimension the count cannot:

| Pattern | Likely meaning |
|---|---|
| Many `0xC0000064` across many different names | User-name guessing or spraying with a list |
| Repeated `0xC000006A` against one real account, no success | Password guessing on a valid account |
| One to three `0xC000006A` followed by a success, same source, minutes apart | Typical forgotten or mistyped password (like my 10:35–10:36 sequence) |
| `0xC000006A` burst followed by a success | **The dangerous one**: guessing that worked. Same shape as a forgotten password, so the source, timing and what the session did next decide it |

Before escalating, I would check the number and spacing of attempts, how many accounts were targeted, the source workstation or IP, the logon type and process, whether a success followed, and whether the account is privileged.

## 9. MITRE ATT&CK Mapping

The scenario resembles these techniques. It was a controlled test; the events do not indicate a compromise.

| Technique | ID | Evidence |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | 4625 with `0xC000006A` (×3) and `0xC0000064` (×5) |
| Create Account: Local Account | T1136.001 | 4720 at 20 Nov 13:05:15 |
| Account Manipulation | T1098 | 4732 and 4733 on Administrators (`S-1-5-32-544`) |
| Valid Accounts: Local Accounts | T1078.003 | 4624 type 2 for `labuser` with 4672 special privileges |

## 10. Detection / Response / Remediation

Detection ideas this data supports (to be built and tested in Project 08):

1. **New local admin:** 4720 followed by 4732 to `S-1-5-32-544` for the same account within 10 minutes. Correlate on the subject's logon ID to see what else that session did. High signal on any workstation.
2. **Any change to Administrators:** 4732 or 4733 on `S-1-5-32-544`. Search by SID, never by group name: the name is language-dependent and the member is recorded as a SID.
3. **User-name guessing:** five or more 4625 with SubStatus `0xC0000064` from one source in 10 minutes.
4. **Guessing that worked:** several 4625 `0xC000006A` for one account followed by a 4624 for the same account.

**Response** if pattern 1 or 4 fired for real: confirm with the account owner, disable the account, review the session's 4688 process history, and remove unexpected group memberships.

**Remediation in my lab:** `labuser` was removed from Administrators, deleted, and its profile folder removed.

## 11. Limitations and Troubleshooting

**Limitations**

- One laptop, one test account, no real attack traffic.
- The two failed-logon tests used different methods and logon types (section 7).
- Findings 5–7 are not resolved.
- The first Splunk account was in recovery during the project; the timeline relies on the second trial and PowerShell.

**Troubleshooting**

| Problem | Cause | Fix | Prevention |
|---|---|---|---|
| Splunk search missed 4732/4733 | Group events record the member as a SID | Added a clause for those event codes on the Administrators group | Search identities by SID as well as by name |
| Splunk and PowerShell times differed by 2 h | Splunk shows Helsinki time, my queries show UTC | Converted to UTC | Set Splunk's display time zone before building timelines |
| `Remove-LocalGroupMember` failed at the start of session 2 | `labuser` was already out of the group | None needed; expected state error | Check state with `Get-LocalGroupMember -SID S-1-5-32-544` first |
| First Splunk account unavailable | Account recovery, a few days according to Splunk | Second trial, forwarder credentials package reinstalled | Keep lab credentials in a password manager; export searches and screenshots as you go |
| Splunk export saved as `.png..csv` | File-name typo | Renamed | Check extensions before saving evidence |

**Cleanup as a forensic lesson:** deleting `labuser` and its profile did not remove its history. Its SID, logons and group changes remain in the Security log. Account deletion is not evidence deletion; only log clearing would be, and that creates event 1102.

## 12. Lessons Learned and Interview Summary

**Lessons**

- An event ID is the start of the question. Status, SubStatus, logon type and linked logon IDs answer it.
- One command can produce five events; one sign-in can produce two 4624s.
- Windows records group members by SID. A search by name alone has a blind spot.
- Never put a secret on a command line when process auditing is on: I would have logged my own password into the SIEM.
- "Unknown" is a valid finding. Making up a cause is not.

**Interview summary (about 70 seconds)**

> I ran a controlled account scenario on my own Windows laptop and investigated it like a SOC case. I created a local account, made it an administrator, failed three logons, logged on, then removed and deleted it, and rebuilt the whole timeline in UTC from PowerShell and Splunk, which matched to the second. The key finding was in the 4625 SubStatus: a wrong password on a real account gives 0xC000006A, a user name that doesn't exist gives 0xC0000064. That one field separates someone mistyping their password from someone guessing user names. I also explained why one admin sign-in produced two 4624 events, the UAC split token, and found that my Splunk search missed the admin-group changes because Windows records the member as a SID, not a name. So I now search by SID. Two events I couldn't explain, I left as Unknown with a test to run next, rather than guessing.

## 13. References

- Microsoft: [4625 An account failed to log on](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- Microsoft: [4624 An account was successfully logged on](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- Microsoft: [4720 A user account was created](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)
- Microsoft: [4732 A member was added to a security-enabled local group](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
- Microsoft: [4798 A user's local group membership was enumerated](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4798)
- MITRE ATT&CK: [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · [T1098](https://attack.mitre.org/techniques/T1098/) · [T1078.003](https://attack.mitre.org/techniques/T1078/003/)
