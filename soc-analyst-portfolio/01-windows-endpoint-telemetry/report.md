# Project 01 — Windows Endpoint Telemetry and SIEM Integration

**Author:** Isaac · **Dates:** 17–19 November 2026 · **Status:** Complete

---

## 1. Overview

I built and validated a telemetry pipeline from a Windows 10 laptop to a cloud SIEM. The laptop generates Windows Security and Sysmon events, a Splunk Universal Forwarder sends only those two logs to Splunk Cloud, and I proved with a marked test event that data arrives unchanged and can be searched. Along the way I found and fixed a Sysmon configuration that was silently blocking every executable on the machine.

## 2. Objectives

1. Verify the endpoint before building anything: OS, Defender, Sysmon, audit policy.
2. Make the key events exist and be useful: process creation with full command lines (4688) and credential checks (4776/4625).
3. Forward only the Security and Sysmon logs to a SIEM.
4. Prove the pipeline end to end: one event with the same time, host and EventCode at the source and in the SIEM.
5. Show that the data answers real questions, using three validation searches.
6. Assess whether Microsoft Sentinel can collect from this endpoint.

## 3. Scope and Authorisation

- **In scope:** my own Lenovo laptop (endpoint), my own MacBook (network test only), and my own Splunk Cloud trial account.
- **Test activity:** harmless and controlled only. I copied a signed Windows binary, ran `cmd.exe /c echo` with a marker string, and made failed logons against a non-existent local account (`labfakeuser`).
- **Not in scope:** any third-party system, exploitation, or malware.

## 4. Lab Environment

| Component | Details |
|---|---|
| Endpoint | Lenovo IdeaPad 320, Windows 10 Home Single Language 22H2, build 19045.6456, 64-bit, Spanish (es-ES) |
| Antivirus | Microsoft Defender: Normal mode, real-time and tamper protection on (McAfee removed on 18 Nov) |
| Endpoint sensor | Sysmon v15.22 (schema 4.91), lab config `sysmon-lab.xml`, hash `C20B9B98…` |
| Forwarder | Splunk Universal Forwarder 10.6.1.1, running as Local System |
| SIEM | Splunk Cloud Platform trial (14 days, 5 GB/day), index `main` |
| Network test | MacBook Pro 2019, macOS, same Wi-Fi network |
| Transport | Outbound TCP 9997 with TLS (destination and certificate from the Splunk Cloud credentials package) |

Architecture diagram: [`architecture.md`](architecture.md).

## 5. Scenario and Hypothesis

**Scenario:** a SOC needs trustworthy endpoint telemetry before it can detect anything.

**Hypothesis:** if auditing and Sysmon are configured correctly, the Security and Sysmon logs record process creation (with command lines) and failed logons. A forwarder can then deliver those events to Splunk with the time, host and event ID unchanged.

**What I expected to observe:**
- 4688 with command lines.
- Sysmon Event 1.
- 4625 paired with 4776 for every failed logon.
- Matching values at both ends of the pipeline.

## 6. Methodology

1. **Baseline (read-only).**
   - Recorded OS, disk, Defender, the Sysmon service and config, and the full audit policy with `baseline.ps1`.
   - Backed up the audit policy before any change (`commands/`).
2. **Fixed the endpoint.**
   - Found and fixed a Sysmon config that blocked all executables (see section 11 and `troubleshooting/`).
3. **Audit policy.**
   - Enabled Process Creation (success), Security Group and User Account Management (success and failure), and Credential Validation (success and failure).
   - Logon, Logoff, Account Lockout and Special Logon were already enabled.
   - I set subcategories by **GUID**, because English names fail on Spanish Windows (error 0x57).
4. **Command lines in 4688.**
   - Windows 10 Home has no Group Policy editor, so I set `ProcessCreationIncludeCmdLine_Enabled = 1` in the registry (`enable-cmdline-4688.ps1`).
   - Proved it with a marked process.
5. **Failed-logon test.**
   - Ran `runas /user:labfakeuser cmd` three times with a wrong password.
6. **Network path.**
   - Ran a TCP 9997 test and ping from the Lenovo to a `nc -l 9997` listener on the MacBook.
   - Tested TCP 9997 from the Lenovo to the Splunk Cloud input host.
7. **Forwarder.**
   - Installed the UF, then installed the credentials package. I typed the password at the prompt instead of using `-auth`, because 4688 now records command lines.
   - Wrote `inputs.conf` with only two inputs (`splunk/inputs.conf`):
     - `renderXml = false`, so Splunk parses `EventCode` and `LogName` without an add-on.
     - `start_from = oldest`, so earlier test events were included.
8. **End-to-end test.**
   - Created a marked 4688 event (`splunk-e2e-test`).
   - Compared it in PowerShell and in Splunk.
9. **Validation searches.**
   - Ran three searches, saved in `splunk/searches.spl`.

## 7. Evidence and Results

| Check | Result | Evidence |
|---|---|---|
| Baseline captured | OS, Defender, Sysmon, audit policy before and after | `baseline.md`, `commands/` |
| Sysmon fix | Config hash `B3B9EFA9…` → `C20B9B98…`; executable copy succeeded (200,704 bytes); 0 Event 27/28 after the fix | `troubleshooting/` |
| 4688 command lines | 18 Nov 15:43:29: `cmd.exe` launched by `powershell.exe`, command line `"C:\WINDOWS\system32\cmd.exe" /c echo cmdline-test` | `2026-11-18_project01_4688-cmdline.png` |
| Failed logons | 3 attempts (error 1326) gave 3 pairs of 4625 + 4776, each pair in the same second (15:59:05, 16:00:10, 16:00:46) | `2026-11-18_project01_4776-4625-failed-logon.png` |
| Lenovo → MacBook | TCP 9997 succeeded, ping 0% loss, TTL 64 | `2026-11-19_project01_network-path.png` |
| Lenovo → Splunk Cloud | `TcpTestSucceeded : True` on 9997 | `2026-11-19_project01_cloud-reach-9997.png` |
| Forwarder | `list forward-server`: one active forward, no inactive ones | `2026-11-19_project01_uf-forwarding.png` |
| Only two sources | 24 h: 109,804 events = Sysmon 103,829 + Security 5,975 | `2026-11-19_project01_splunk-sources.png` |
| End to end | See table below | `…_e2e-source.png`, `…_e2e-splunk.png` |
| Searches | Search 1 (unfiltered run) returned 3,821 events of type 4688; its top row is an older event from before the command-line fix. Search 2 returns Sysmon Event 1. Search 3 counts 7 failed logons. | `…_spl-4688.png`, `…_spl-sysmon1.png`, `…_spl-4625.png` |
| Command lines reach Splunk | Searching Splunk for `splunk-e2e-test` found the event. That marker exists **only** in the command-line field, so the match proves the command line was forwarded | `2026-11-19_project01_e2e-splunk.png` |

**End-to-end test (item 05):**

| Field | PowerShell (source) | Splunk (SIEM) | Match |
|---|---|---|---|
| Time | 13:48:36 | 13:48:36.873 | Yes |
| Host | laptop hostname (masked) | same | Yes |
| EventCode | 4688 | 4688 | Yes |

## 8. Analysis and Findings

**Proven:**
- The endpoint records process creation with full command lines, and correlated failed-logon events.
- The forwarder sends exactly the two intended logs.
- An event arrives in Splunk with the same time, host and event ID.

**Finding 1: the time zone, not the pipeline.** Splunk first showed the test event at 11:48:36, exactly two hours early. My Splunk display time zone was UTC, while the laptop runs on Europe/Helsinki time. After I changed **Preferences → Time zone**, the times matched. A whole-hour offset points to display settings, not data loss. Misreading it would put every event in an investigation timeline in the wrong place.

**Finding 2: seven failed logons, only three were mine.** Search 3 counted 7 events of type 4625 between 16 Nov 14:32:07 and 19 Nov 09:14:58, local time. The search screenshot shows 12:32:07 and 07:14:58, because it was taken in UTC, before the time-zone fix in Finding 1. Reading each raw message:

| Count | Source | Assessment |
|---|---|---|
| 3 | My `runas` test with `labfakeuser` (18 Nov 15:59–16:00) | Expected test activity |
| 2 | Browser password checks by Edge and Chrome (16 Nov) | Benign |
| 1 | A disabled Guest account lookup from Explorer (17 Nov) | Benign |
| 1 | A system-initiated failure at the lock screen (19 Nov) | Benign |

None had a remote source address. **A count alone cannot separate a test, normal noise and an attack: the message has to be read.** This directly shapes the brute-force thresholds in Project 08.

**Finding 3: the network is not isolated.** The Lenovo reached the MacBook on TCP 9997 with 0% ping loss. The Wi-Fi network does **not** block device-to-device traffic, which Project 06 (network reconnaissance) depends on.

The ping replies carried **TTL 64**, the starting value macOS uses. No router decremented it, so the two machines sit on the same subnet with no hop between them.

**Finding 4: the monitoring agent monitors itself.** Search 2 shows Sysmon Event 1 for the forwarder's own helper processes (`splunk-netmon.exe`, `splunk-MonitorNoHandle.exe`, started by `splunkd.exe` as SYSTEM). Every agent adds its own noise. Excluding it in Project 03 must use the full path **and** the parent process, because a filter on the file name alone is an easy hiding place for an attacker.

**Unknown:** why the command-line registry value had disappeared by the afternoon of 18 Nov, after it was set at 11:49 (section 11).

## 9. MITRE ATT&CK Mapping

This project builds **visibility**, not detections of real attacks. The mapping shows which techniques the collected telemetry can now support.

| Technique | ID | Telemetry now available | Evidence |
|---|---|---|---|
| Brute Force: Password Guessing | T1110.001 | 4625 + 4776 pairs, countable per host in Splunk | Failed-logon test, search 3 |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | 4688 and Sysmon 1, with full command lines | `cmdline-test`, `splunk-e2e-test` |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Sysmon config hash, Event 16 (config change), Events 27/28 | Sysmon troubleshooting case |
| Impair Defenses: Disable Windows Event Logging | T1562.002 | Two independent process sources (4688 + Sysmon 1); a gap between them is a signal | Section 10 |

## 10. Detection / Response / Remediation

Detection ideas this pipeline now supports. They will be built and tested in later projects.

1. **Failed-logon burst:** at least 5 events of 4625 for one account or host within 10 minutes. Read the messages before escalating (Finding 2). This becomes Project 08.
2. **Sysmon block event:** any Sysmon Event 27 or 28 is high-signal. Either an attack was stopped, or the configuration is wrong.
3. **Sensor silence:** 4688 keeps arriving but Sysmon Event 1 stops for a host. That suggests Sysmon was stopped or tampered with.
4. **Log clearing:** Security Event 1102 on any host.

**Remediation applied:**
- Removed the blocking behaviour from the Sysmon config.
- Restored command-line logging.
- Limited forwarding to two logs.

## 11. Limitations and Troubleshooting

**Limitations:**
- The forwarder runs as **Local System**, a lab trade-off for reading the Security log. Production would use a least-privileged account with read-only event-log access.
- The Sysmon config still logs nearly everything (103,829 events in 24 h), which is noisy. A tuned config is planned for Project 03.
- The Splunk Cloud trial is limited to 14 days and 5 GB/day.
- In the classic event format, the account-name field was not cleanly extracted, because the 4625 message holds two account-name blocks (subject and target). A `rex` extraction is needed for per-account counting.
- Windows 10 22H2 is past end of support, so this laptop is a lab endpoint only.
- Sentinel was not deployed (see `sentinel/feasibility.md`).

**Troubleshooting log:**

| Problem | Cause | Fix | Prevention |
|---|---|---|---|
| Tools would not install; no error shown | Sysmon `FileBlockExecutable`/`FileBlockShredding` set to an empty `exclude`, which blocks everything | Changed both to `include`; verified with config hash, copy test, 0 block events | Review blocking event types before deploying any Sysmon template. Full write-up: `troubleshooting/sysmon-27-28-self-block.md` |
| `auditpol` error 0x00000057 | English subcategory names on Spanish Windows | Used Spanish names, then GUIDs | Always use GUIDs in scripts |
| 4688 command line empty again | Registry value missing on 18 Nov afternoon (cause unknown) | Re-applied it; the test passed without a reboot | Re-verify settings with a test event, not just the configuration |
| `.ps1` scripts would not arrive by email | Gmail blocks script attachments (a real email security control) | Recreated the files locally with PowerShell here-strings | Move scripts by file, never by email |
| Private files inside the portfolio folder | Used "Move" instead of "Copy" | Moved them back to the private folder | Keep separate raw and portfolio folders; check before publishing |
| Forwarder password rejected | Typo on the first attempt | Second attempt worked | Password manager |
| Test event "missing" in PowerShell | Event fell outside the 2-minute search window | Widened it to 10 minutes | Allow for delay when searching just-created events |
| Splunk times 2 h early | Display time zone set to UTC | Set Europe/Helsinki in Preferences | Check the time zone before building timelines |
| Command errors | Typed `Test/path` instead of `Test-Path`; pasted two commands on one line | Corrected and re-ran | Run one command per line |
| First ping to the MacBook failed ("host not found") | A name was typed instead of the IP address | Re-ran with the IP: 0% loss | Copy the IP from the Mac output |
| Search 1 showed a 4688 with an empty command line | The top result was an older event from before the command-line fix | Filtered the saved search to the two test markers (`splunk/searches.spl`). The screenshot keeps the unfiltered run as the "before" view | Make validation searches target the test event, not "any recent event" |

**Process note:** the Sysmon registry backup was taken after the first configuration change, so it holds the fixed config. The original file is kept for rollback. In proper change management, the backup comes first.

## 12. Lessons Learned and Interview Summary

**Lessons:**
- A setting proves nothing until a test event proves it.
- A security tool can break the system it monitors, and do it silently. The evidence was in its own log.
- Before trusting SIEM times, check the display time zone.
- A count of events is not a finding; reading the events is.
- Collect only what you need: two logs, chosen on purpose.

**Interview summary (about 75 seconds):**

> I built a Windows-to-SIEM telemetry pipeline in my home lab. First I baselined the endpoint, and found that my Sysmon config was silently blocking every executable. I reproduced it with a harmless file copy, matched it to Sysmon Event 27 in the same second, fixed one setting, and verified the fix. Then I enabled the audit policies a SOC relies on, including command-line capture in 4688 and credential validation, and proved each with a controlled test: three failed logons gave three matched 4625 and 4776 pairs. I forwarded only the Security and Sysmon logs to Splunk Cloud and proved the pipeline end to end: one marked event had the same time, host and event ID on both sides. The two-hour gap I first saw was Splunk's time zone setting, not data loss. Finally, my failed-logon search returned seven events, but reading them showed only three were my test. That's why I don't treat a count as a finding.

## 13. References

- Splunk: [Install a Windows universal forwarder](https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/10.4/install-the-universal-forwarder)
- Splunk: [Install the Splunk Cloud Platform universal forwarder credentials package](https://help.splunk.com/en/data-management/onboard-data-to-splunk-enterprise/universal-forwarder-manual/9.0/configure-the-universal-forwarder/install-and-configure-the-splunk-cloud-platform-universal-forwarder-credentials-package)
- Splunk: [Splunk Enterprise 10.4 system requirements](https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.4/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises)
- Microsoft: [Get-WinEvent](https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent) · [Test-NetConnection](https://learn.microsoft.com/powershell/module/nettcpip/test-netconnection) · [Get-NetIPConfiguration](https://learn.microsoft.com/powershell/module/nettcpip/get-netipconfiguration)
- Microsoft: [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- Microsoft: [Azure Monitor Agent on Windows clients](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-windows-client) · [Microsoft Sentinel billing](https://learn.microsoft.com/azure/sentinel/billing)
- MITRE ATT&CK: [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · [T1059.003](https://attack.mitre.org/techniques/T1059/003/) · [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · [T1562.002](https://attack.mitre.org/techniques/T1562/002/)
