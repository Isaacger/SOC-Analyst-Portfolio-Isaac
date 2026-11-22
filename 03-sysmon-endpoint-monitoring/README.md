# Project 03: Sysmon Endpoint Monitoring

**Goal:** turn Sysmon from a "log everything" sensor into a curated one, then prove it still sees process, network, file and DNS activity.

## Results

| Deliverable | Result |
|---|---|
| Config hash before / after | `C20B9B98...` / `196066F4...` (applied 16:21:36 UTC, Sysmon Event 16) |
| Noise before | 528,834 events in 24 h (about 22,035 per hour) |
| Noise after | 232 events in 1 h (about 1% of the old hourly rate, 99% less) |
| Exclusions | 6 exact-path rules (`Image is`) for the Splunk forwarder: 4 in ProcessCreate, 2 in FileCreate |
| Test events | Events 1, 3, 11 and 22 all logged |
| Process tree | powershell.exe > cmd.exe > whoami.exe, proven by ProcessGuid / ParentProcessGuid |
| Detection ideas | T1059.001 (PowerShell spawning cmd), T1033 (whoami), T1105 (PowerShell network + Downloads file), each with a false positive |

## Noise after: what is left

Event 1 = 198, Event 3 = 16, Event 22 = 10, Event 11 = 7, Event 13 = 1. My own tests are included in these 232 events.

## Honest findings

- Most of the drop came from the baseline's include rules, not from my six exclusions.
- Events 7, 10, 12 and 13 are now mostly off, so DLL loads, LSASS access and most registry changes are blind spots.
- Event 11 was not logged once when Set-Content overwrote an existing file, but Microsoft documents overwrites as logged and later attempts did log. Unknown until a control test.
- Event 10 is fully off, so LSASS access (credential theft, T1003.001) is a blind spot. Next step: a targeted rule for lsass.exe.
- Reading the Sysmon log needs admin. A standard window returned "no events found", which looked like missing data but was not.

## Files

- `report.md`: full report
- `config/sysmon-before.xml`, `config/sysmon-p03.xml`: old and curated configs
- `commands/`: apply-and-verify, test-events, query-sysmon-events
- `splunk/searches.spl`: noise before/after and forwarder searches

## Screenshots (`screenshots/`)

- `2026-11-22_project03_config-after.png`: sysmon64 -c: new hash 196066F4
- `2026-11-22_project03_config-before.png`: sysmon64 -c: old hash C20B9B98
- `2026-11-22_project03_field-guide.png`: Event 1 of cmd.exe: the six fields
- `2026-11-22_project03_forwarder-processes.png`: Splunk: every forwarder binary by EventCode
- `2026-11-22_project03_forwarder-rules.png`: the six forwarder exclusion rules in the XML
- `2026-11-22_project03_noise-after.png`: Splunk: events by ID, 1 h after
- `2026-11-22_project03_noise-before.png`: Splunk: events by ID, 24 h before
- `2026-11-22_project03_process-tree.png`: GUID chain powershell > cmd > whoami
- `2026-11-22_project03_repo-config-hashes.png`: repo config files match the applied hashes
- `2026-11-22_project03_test-events.png`: Events 3, 11 and 22 from the tests
