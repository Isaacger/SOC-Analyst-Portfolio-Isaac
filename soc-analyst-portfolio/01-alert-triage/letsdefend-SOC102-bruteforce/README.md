# LetsDefend SOC176 – RDP Brute Force Detected

| Field                 | Value                                                    |
| --------------------- | -------------------------------------------------------- |
| **Category**          | Alert Triage                                             |
| **Platform / Source** | LetsDefend                                               |
| **Date completed**    | 2026-11-15                                               |
| **Status**            | Completed                                                |
| **Difficulty**        | Medium                                                   |
| **Tools used**        | LetsDefend SIEM, Log Management, VirusTotal, APNIC WHOIS |
| **MITRE ATT&CK**      | T1110 – Brute Force; T1078 – Valid Accounts              |
| **Verdict**           | True Positive                                            |

---

## 1. Executive Summary

I investigated a medium-severity RDP Brute Force alert in LetsDefend (SOC176). The investigation identified suspicious authentication activity originating from external IP address `218.92.0.56`, targeting the internal Windows host `172.16.17.148` over TCP port 3389.

I correlated firewall logs with Windows Security events and identified failed authentication attempts (Event ID 4625), followed by a successful RDP authentication (Event ID 4624) using the Matthew account. Based on the Playbook criteria, I classified the alert as a True Positive because successful authentication occurred following failed login attempts from the same source IP against the same target.

No evidence of lateral movement was identified in the logs examined.

## 2. Scenario / Alert Details

- **Alert name / rule:** SOC176 – RDP Brute Force Detected
- **Event ID:** 234
- **Severity:** Medium
- **Alert type:** Brute Force
- **Trigger time:** 2024-03-07 11:44:00 (+03:00)
- **Investigation completed:** 2026-11-15
- **Affected host:** Matthew
- **Affected host IP:** `172.16.17.148`
- **Target account:** Matthew
- **Source IP:** `218.92.0.56`
- **Destination port:** TCP/3389
- **Protocol:** RDP
- **Firewall action:** Allowed
- **Final verdict:** True Positive

## 3. Investigation Steps

### Step 1 – Source IP Classification

I started by examining the source IP address to determine whether the activity originated from an internal or external network.

Source IP: `218.92.0.56`

I checked the address against private IPv4 ranges and confirmed that it was an external public IP.

I also examined its WHOIS registration using APNIC.

**WHOIS findings:**

- Country: China
- ISP: China Telecom
- Network: CHINANET Jiangsu
- ASN: AS4134
- Abuse contact: [anti-spam@chinatelecom.cn](mailto\:anti-spam@chinatelecom.cn)

### Step 2 – IP Reputation Check

I investigated the source IP using VirusTotal to identify whether it had previously been associated with malicious activity.

According to the LetsDefend investigation results, 11 antivirus engines flagged the IP as malicious.

This supported treating the source as suspicious, although reputation results alone do not establish malicious activity.

### Step 3 – Traffic Analysis

I searched for `218.92.0.56` in LetsDefend Log Management.

I identified 15 firewall log entries originating from this address.

The events showed:

- Source IP: `218.92.0.56`
- Destination IP: `172.16.17.148`
- Destination port: `3389`
- Protocol: RDP
- Firewall action: Allowed

This confirmed repeated RDP related connection attempts targeting the same internal host.

### Step 4 – Authentication Log Analysis

I examined Windows Security logs to determine whether the authentication attempts were successful.

**Event ID 4625 – Failed Logon**

I identified failed authentication attempts involving:

- Username: Matthew
- Username: sysadmin
- Source IP: `218.92.0.56`

The observed error codes included:

- `0xC000006A` – Incorrect password.
- `0xC000006D` – General logon failure.

**Event ID 4624 – Successful Logon**

I identified a successful authentication involving:

- Username: Matthew
- Source IP: `218.92.0.56`
- Destination IP: `172.16.17.148`
- Logon Type: 10 (RemoteInteractive)

Logon Type 10 is consistent with an RDP session.

The successful authentication following failed attempts from the same source IP against the same target matched the LetsDefend Playbook criteria for a successful brute-force attack.

### Step 5 – Determine the Scope

I investigated whether the source IP attempted to access multiple internal systems.

The available firewall logs identified one target host: `172.16.17.148` (Matthew).

I did not identify evidence of the attacker targeting multiple internal hosts.

**Finding:** The observed attack scope was limited to one identified destination.

### Step 6 – Post-Authentication Investigation

I examined additional authentication events to identify possible activity following the successful login.

The attacker attempted to authenticate using additional accounts, including sysadmin, but those attempts failed.

I did not identify evidence of successful authentication to other internal systems or confirmed lateral movement in the logs examined.

## 4. Evidence & Screenshots

| # | Description                                      | File                                       |
| - | ------------------------------------------------ | ------------------------------------------ |
| 1 | Original RDP Brute Force alert                   | `screenshots/01-alert-details.png`         |
| 2 | Source IP WHOIS information                      | `screenshots/02-whois-lookup.png`          |
| 3 | VirusTotal IP reputation results                 | `screenshots/03-virustotal-reputation.png` |
| 4 | Firewall traffic showing RDP connections         | `screenshots/04-firewall-logs.png`         |
| 5 | Event ID 4624 – Successful authentication        | `screenshots/05-successful-logon.png`      |
| 6 | Event ID 4625 – Failed authentication (Matthew)  | `screenshots/06-failed-logon-matthew.png`  |
| 7 | Event ID 4625 – Failed authentication (sysadmin) | `screenshots/07-failed-logon-sysadmin.png` |
| 8 | Destination host identification                  | `screenshots/08-destination-host.png`      |

## 5. Indicators of Compromise (IOCs)

| Type           | Value (defanged)  | Context                                 | Reputation                |
| -------------- | ----------------- | --------------------------------------- | ------------------------- |
| Source IP      | `218.92.0[.]56`   | External RDP source                     | 11 VT detections reported |
| Destination IP | `172.16.17[.]148` | Internal target host                    | Internal address          |
| Hostname       | Matthew           | Target Windows host                     | N/A                       |
| Username       | Matthew           | Successfully authenticated account      | N/A                       |
| Username       | sysadmin          | Additional failed authentication target | N/A                       |
| Port           | TCP/3389          | RDP service                             | N/A                       |

**Note:** No malicious file hashes, domains or URLs were identified during this investigation.

## 6. Timeline (UTC)

| Time       | Event                                             | Source                |
| ---------- | ------------------------------------------------- | --------------------- |
| 2024-03-07 | Suspicious RDP activity identified                | Firewall logs         |
| 2024-03-07 | Multiple RDP-related firewall events recorded     | Log Management        |
| 2024-03-07 | Failed authentication attempts recorded           | Windows Event ID 4625 |
| 2024-03-07 | Successful authentication to Matthew identified   | Windows Event ID 4624 |
| 2024-03-07 | Additional failed authentication against sysadmin | Windows Event ID 4625 |
| 2026-11-15 | Investigation and alert closure                   | LetsDefend            |

*The individual authentication event timestamps should be added from the original logs when available. The exact sequence is based on the correlated evidence.*

## 7. Analysis & Findings

The investigation identified suspicious RDP activity originating from an external IP address associated with China Telecom.

Firewall logs showed 15 events targeting the internal Windows host `172.16.17.148` over TCP port 3389.

I correlated these network events with Windows Security logs and identified failed authentication attempts (Event ID 4625), followed by a successful authentication (Event ID 4624) using the Matthew account.

The successful authentication was associated with Logon Type 10, confirming a RemoteInteractive login consistent with RDP.

Additional authentication attempts against sysadmin were unsuccessful.

**MITRE ATT&CK mapping:**

- **T1110 – Brute Force:** Repeated authentication attempts against the target account and additional usernames.
- **T1078 – Valid Accounts:** Successful authentication using the Matthew account.

The precise credential acquisition method was not established. No evidence of lateral movement, persistence or data exfiltration was identified in the available logs.

## 8. Verdict & Justification

**Verdict: TRUE POSITIVE**

I classified this alert as a True Positive because:

1. The source IP was external and had suspicious threat intelligence reputation.
2. Firewall logs confirmed repeated RDP-related traffic targeting the internal host.
3. Windows Event ID 4625 recorded failed authentication attempts.
4. Windows Event ID 4624 confirmed successful authentication using the Matthew account.
5. Logon Type 10 confirmed a RemoteInteractive session.

The evidence supports successful suspicious RDP access according to the LetsDefend Playbook.

However, the exact method used to obtain the credentials remains unconfirmed.

## 9. Response & Containment

The LetsDefend Playbook recommended isolating the affected device.

Recommended response actions:

- [ ] Disable or restrict the potentially compromised Matthew account.
- [ ] Reset the affected account credentials.
- [ ] Block the suspicious source IP at the appropriate network security controls.
- [ ] Preserve Windows Security and firewall logs.
- [ ] Review account privileges and investigate post-authentication activity.
- [ ] Escalate the incident to Tier 2 / Incident Response.

These are recommended containment actions; they should not be interpreted as actions I personally executed during the LetsDefend exercise.

## 10. Detection & Prevention Recommendations

To reduce the likelihood of similar incidents, I recommend:

- Restricting direct public access to RDP.
- Enforcing Multi-Factor Authentication (MFA).
- Using VPN or Zero Trust access for remote administration.
- Implementing strong password and account lockout policies.
- Enabling Network Level Authentication (NLA).
- Applying least-privilege access.
- Implementing network segmentation.
- Monitoring repeated failed authentication attempts followed by successful logins.
- Creating SIEM correlation rules for suspicious RDP authentication patterns.

## 11. Lessons Learned

Through this investigation, I learned the importance of correlating firewall activity with Windows authentication events instead of relying solely on the initial alert.

I gained practical experience identifying external IP addresses, examining WHOIS information, reviewing IP reputation, analysing firewall logs, and interpreting Windows Security Event IDs 4624 and 4625.

One important takeaway was understanding the difference between successful unauthorized access and confirmed lateral movement. Although the attacker successfully authenticated to the Matthew host, I did not identify evidence of further internal movement in the available logs.

This investigation improved my understanding of RDP brute force detection, authentication analysis, attack scope assessment and evidence based incident classification.

## 12. References

- LetsDefend – SOC176 RDP Brute Force Detected.
- APNIC WHOIS – [https://wq.apnic.net/](https://wq.apnic.net/)
- VirusTotal – [https://www.virustotal.com/](https://www.virustotal.com/)
- Microsoft – Windows Security Auditing, Event ID 4624 and 4625.
- MITRE ATT&CK – T1110: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)
- MITRE ATT&CK – T1078: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)
