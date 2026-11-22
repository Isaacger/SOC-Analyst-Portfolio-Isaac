# Project 03: Sysmon Endpoint Monitoring - Report

## 1. Objective
Turn Sysmon from a "log everything" sensor (528,834 events in 24 h) into a curated one, then prove it still sees process, network, file and DNS activity. I measured the noise before and after, and ran four test commands to look for blind spots.

## 2. Environment
- Lenovo IdeaPad 320 laptop (physical endpoint), Windows 10 Home 22H2, Sysmon v15.22 (schema 4.91), Splunk Universal Forwarder, Splunk Cloud
- Base config: SwiftOnSecurity `sysmonconfig-export.xml` (version 74, July 2021, schema 4.50), saved as `sysmon-p03.xml`

**Scope and authorisation:** my own laptop and my own Sysmon configuration only. All test commands were harmless (a `whoami`, a TCP connection to example.com, a DNS lookup, a one-line `.ps1` in my Downloads folder). The rollback file restores the previous configuration exactly.
- Tests ran in a normal (non-admin) PowerShell. Reading the Sysmon log needed admin.

## 3. Before state
- Running config hash: `C20B9B98...` (file `sysmon-lab.xml`).
- The rollback file `sysmon-lab-BEFORE.xml` has an identical SHA256, so rollback restores the exact "before" state.
- Noise in the last 24 h: 528,834 events (about 22,035 per hour) across 17 event IDs. Events 12, 10, 13 and 7 made up 89% of the total.
- The Splunk forwarder produced about 63,500 events (roughly 12%). Sysmon64.exe, lsass.exe and svchost.exe were bigger sources.
- Evidence: `noise-before.png`, `forwarder-processes.png`, `config-before.png`

## 4. Config changes
Exclusions use `condition="is"` with the full path. A rule like `end with splunkd.exe` would also hide an attacker's copy in `C:\Users\Public\`. The forwarder runs from an admin-only folder.

| Section | Rule (Image is, full path under `C:\Program Files\SplunkUniversalForwarder\bin\`) | Reason |
|---|---|---|
| ProcessCreate (Event 1) | splunk-admon.exe, splunk-netmon.exe, splunk-powershell.exe, splunk-regmon.exe | Forwarder helper processes, about 720 events a day |
| FileCreate (Event 11) | splunk-winevtlog.exe, splunkd.exe | Checkpoint and tracker files in the forwarder's own folder. Defensive: the baseline's include rules probably did not match them anyway. |

Other decisions:
- No ImageLoad (Event 7) rule. That section is `include` with no rules, so Event 7 is off. An `Image is` rule there would have turned logging on for those processes.
- No NetworkConnect or DnsQuery exclusions. Forwarder DNS is one event a day, so it is not noise.
- FileBlockExecutable and FileBlockShredding are absent. An empty exclude there would block every executable.
- Events 1, 3, 11 and 22 stay enabled. Event 1 shows command lines and parents, Event 3 shows which process connected out, Event 11 shows files created in risky folders, and Event 22 shows DNS from the process that asked.

## 5. Apply and verify
- Applied with `sysmon64 -c C:\LabEvidence\sysmon-p03.xml`. Sysmon reported the file validated and the configuration updated.
- New hash: `196066F4...`. Change time: 16:21:36 UTC (Sysmon Event 16).
- The repo copies of both XML files match the hashes of the configs that ran.
- Evidence: `config-after.png`, `forwarder-rules.png`, `repo-config-hashes.png`

## 6. Test events
All four event types were logged under the curated config.

| Test | Event | Result |
|---|---|---|
| `cmd /c "whoami & echo p03-chain-test"` | 1 | cmd.exe and whoami.exe both logged |
| `Test-NetConnection example.com -Port 443` | 3 | powershell.exe, port 443, logged |
| `Resolve-DnsName p03-dns-test.example.com` | 22 | Logged. QueryStatus 9501 and an SOA result: the query completed, the name has no record. |
| `Set-Content ...\Downloads\p03-test.ps1` | 11 | Logged on first creation (RuleName: Downloads) |

My predictions for tests 3 and 4 were wrong. I read "an exclude rule matches" as "logged", but in an exclude section a match drops the event.

Event 11 was not logged when `Set-Content` overwrote the existing file at 17:08. It was logged again after I deleted and recreated the file. Microsoft's Sysmon documentation says FileCreate logs files that are created **or overwritten**, so my single observation conflicts with the vendor's description. My test-events screenshot also shows four more Event 11s for the same file (17:19:28, 17:22:00, 17:26:42, 17:53:40). **Unknown** until a control test settles it.

Evidence: `test-events.png`

## 7. Process tree (from GUIDs)

    powershell.exe   ProcessGuid {d7d569c4-2165-6b03-7b21-000000000700}
     +- cmd.exe      ParentProcessGuid {...2165-6b03-7b21...}   ProcessGuid {d7d569c4-2174-6b03-7f21-000000000700}
         +- whoami.exe   ParentProcessGuid {...2174-6b03-7f21...}   ProcessGuid {d7d569c4-2174-6b03-8021-000000000700}

All three ran at Medium integrity. GUIDs are better than process IDs because Windows reuses PIDs and never reuses GUIDs. The same powershell.exe GUID also appears in my Event 3 and Event 22 records.

Evidence: `process-tree.png`

## 8. Field guide (my Event 1 for cmd.exe)
- **Image:** the executable that ran and where it lives. cmd.exe in `C:\Windows\System32\` is normal, the same name in `C:\Users\Public\` is not.
- **ParentImage:** which program started it. cmd.exe from powershell.exe can be normal, from winword.exe it is suspicious.
- **CommandLine:** the arguments, which show intent. Here `whoami` is a user-discovery command.
- **Hashes:** MD5, SHA256 and IMPHASH identify the file itself. A renamed copy has a different path but the same hash, and the hash can be looked up on a reputation service.
- **ProcessGuid:** a unique ID for this process instance, so I can follow it even if a process ID is reused.
- **User:** the account whose security context ran it. Together with IntegrityLevel (Medium, a normal user) it shows the privilege level.

Evidence: `field-guide.png`

## 9. Noise after
| | Events | Per hour |
|---|---|---|
| Before (24 h average) | 528,834 | about 22,035 |
| After (1 h, 16:31-17:31 UTC) | 232 | 232 |

After the change, five event IDs remain: Event 1 = 198, Event 3 = 16, Event 22 = 10, Event 11 = 7, Event 13 = 1. That is about a 99% reduction per hour (232 / 22,035 = 1.05%). My own tests are included in the 232.

Most of the drop comes from the baseline's include rules, not from my six forwarder exclusions. Events 12, 10 and 7 are now mostly off.

Evidence: `noise-before.png`, `noise-after.png`

## 10. Detection ideas
| Idea | ATT&CK | Event | False positive | How to tell it apart |
|---|---|---|---|---|
| PowerShell spawning cmd.exe | T1059.001 (T1059.003 is the closer match for cmd) | 1 | Admins and scripts running normal commands | Check the parent of PowerShell and the command line |
| whoami.exe execution | T1033 | 1 | IT support checking which account they use | Look for a burst of discovery commands (net user, ipconfig, systeminfo) |
| PowerShell network connection, then a file in Downloads from the same ProcessGuid | T1105 | 3 + 11 | Update-Help or module installs | Check the destination host and the file |

My test created the file locally, so it shows the pattern, not a real transfer. PowerShell's own `__PSScriptPolicyTest_*.ps1` in Temp is a `.ps1` created by powershell.exe. The Downloads folder condition keeps it from firing.

## 11. Limitations
- Most of the noise reduction came from the baseline, not from my exclusions.
- Under the old config, splunkd.exe produced 162 Event 3s a day. Under the new config it is probably no longer logged, because no NetworkConnect include rule matches the forwarder's folder, so forwarder connections to Splunk Cloud are likely invisible (not yet verified with a search).
- Events 7, 10, 12 and 13 are mostly off. DLL loads and process access are blind spots, and most registry changes too, although the baseline still includes persistence keys such as `CurrentVersion\Run`.
- Event 10 is completely off, so an attacker reading LSASS memory to steal credentials (T1003.001) would not appear. Next step: a targeted Event 10 include rule for `TargetImage` lsass.exe, instead of logging all process access again.
- The baseline dates from 2021 (schema 4.50), so it has no rules for newer Sysmon events such as 26 and 29.
- Project 01 recorded 103,829 Sysmon events in 24 h under the same config hash; this baseline is about five times higher. Not yet reconciled.
- Before is a 24 h average. After is a single hour that includes my tests.
- The Event 11 overwrite behaviour was not retested with a control.
- The meaning of QueryStatus 9501 (DNS_INFO_NO_RECORDS) is unverified.
- Event 3's log time differed between `TimeCreated` and the event's `UtcTime` field. I describe the link to Event 22 as "same ProcessGuid, within seconds".

## 12. Lessons
- Reading the Sysmon log needs admin. In a standard window, `Get-WinEvent` returned "no events found" and UnauthorizedAccessException, which looks like missing data but is not.
- My `Where-Object` marker filter hid whoami.exe and Event 3, because their fields do not contain the marker. A "missing event" was a query problem.
- Check which section is live before writing a rule. In an include section, an `Image is` rule turns logging on.

## 13. Conclusion
The curated config cut Sysmon volume by about 99% per hour and still logged process creation, network connections, file creation and DNS from my tests. The cost is visibility into image loads, process access and registry activity.

## 14. Findings by evidence level
| Finding | Label |
|---|---|
| The curated config is running (hash 196066F4, repo copy identical) | Confirmed |
| Sysmon volume fell from about 22,035 to 232 events per hour | Observed (different window lengths, see Limitations) |
| Events 1, 3, 11 and 22 are still logged for my tests | Observed |
| powershell.exe > cmd.exe > whoami.exe is one chain | Confirmed (GUIDs) |
| Most of the reduction came from the baseline, not my exclusions | Interpretation (forwarder events were about 12% of the total) |
| Forwarder network connections are no longer logged | Hypothesis |
| Event 11 does not log overwrites | Unknown (conflicts with Microsoft's documentation) |

## 15. Interview summary
> My Sysmon sensor was logging everything, about half a million events a day, and most of it was registry, process-access and DLL-load noise, including the Splunk forwarder watching itself. I replaced it with the SwiftOnSecurity baseline plus six exclusions for the forwarder, written as exact paths, because an exclusion by file name alone is a hiding place for anyone who names their malware splunkd.exe. Volume dropped about 99%, and I tested that process creation, network, file and DNS events still came through, then rebuilt a powershell to cmd to whoami chain from process GUIDs. I'm honest about the trade-off: most of the drop came from the baseline, not my rules, and I turned off process access entirely, which means LSASS credential theft is now a blind spot. My next change would be a targeted rule for LSASS instead of logging every process access again.

## 16. References
- Microsoft Sysinternals: Sysmon documentation, https://learn.microsoft.com/sysinternals/downloads/sysmon
- SwiftOnSecurity sysmon-config, https://github.com/SwiftOnSecurity/sysmon-config
- MITRE ATT&CK: T1059.001, T1059.003, T1033, T1105, T1003.001, https://attack.mitre.org/
