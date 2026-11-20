# Cybersecurity Portfolio: SOC Analyst

Hands-on projects from my home lab, built to show the practical skills of a Junior SOC / Security Analyst: collecting endpoint telemetry, investigating events, building detections, and documenting findings so another analyst can reproduce them.

Every project includes the commands I ran, the evidence I collected, what the evidence proves (and what it doesn't), and the problems I hit along the way.

## Projects

| # | Project | Focus | Status |
|---|---|---|---|
| 01 | [Windows Endpoint Telemetry and SIEM Integration](01-windows-endpoint-telemetry/) | Sysmon, Windows audit policy, Splunk Universal Forwarder, end-to-end log validation | ✅ Complete |
| 02 | Windows Security Event Investigation | Logon and account activity, timelines | Planned |
| 03 | Sysmon Endpoint Monitoring | Process and network telemetry, config tuning | Planned |
| 04 | Splunk Windows Log Investigation | SPL, field validation, alerts, dashboards | Planned |
| 05 | Sentinel Azure SOC Investigation | KQL, analytics rules, incidents | Planned |
| 06 | Network Reconnaissance | Nmap discovery and service enumeration (lab only) | Planned |
| 07 | Wireshark Traffic Investigation | DNS, TCP, HTTP analysis | Planned |
| 08 | Brute Force Detection Engineering | Failed-logon detections in SPL and KQL, thresholds | Planned |
| 09 | Phishing Investigation | Headers, URLs, IOCs, verdict | Planned |
| 10 | Malware Static Analysis | Hashes, strings, imports (safe samples only) | Planned |
| 11 | Vulnerability Assessment | Scanning an isolated vulnerable target, prioritised findings | Planned |
| 12 | MITRE Detection Mapping and SOC Automation | ATT&CK-mapped detections, Python/PowerShell tooling | Planned |

## Practice labs

Guided exercises from SOC training platforms (mainly LetsDefend) are in [practice/](practice/). They are kept separate from the numbered projects above, which I built and evidenced in my own lab.

## Lab

| Role | System |
|---|---|
| Windows endpoint | Lenovo laptop, Windows 10, Sysmon, Microsoft Defender |
| Analyst workstation | MacBook Pro, macOS |
| SIEM | Splunk Cloud; Microsoft Sentinel planned for Project 05 |

## Ground rules

- All testing is done only on devices and accounts I own.
- No vulnerable target is ever exposed to the internet.
- Published evidence is sanitised: no usernames, hostnames, email addresses, SIDs, full IP addresses or credentials.
