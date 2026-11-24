# Project 04: Windows Security Investigation with Splunk

**Goal:** investigate Windows Security and Sysmon telemetry in Splunk Cloud, identify authentication and account-management activity, validate a scheduled failed-logon alert, and present the findings in a three-panel dashboard.

## Results

| Deliverable | Result |
|---|---|
| SIEM | Splunk Cloud |
| Data sources | Windows Security + Sysmon Operational |
| Windows Security events | 4624, 4625, 4720, 4732 |
| Sysmon events | 1 (Process Create), 3 (Network Connection), 22 (DNS Query) |
| Saved searches | 7 investigation searches |
| Scheduled alert | 3+ failed logons per account in 15 minutes |
| Alert validation | 4 failures detected for `labfakeuser` |
| Alert status | Successfully triggered |
| Alert throttle | 30 minutes per `failed_account` |
| Dashboard | 3 panels, Last 30 days |
| Evidence | Search results, alert configuration, triggered alert and dashboard screenshots |

## Investigation coverage

| Area | Windows Event / Telemetry | Objective |
|---|---|---|
| Authentication | 4625 | Identify failed logons by account and status |
| Authentication | 4624 | Examine successful logons and logon types |
| Account management | 4720 | Detect local account creation |
| Privilege management | 4732 | Investigate Administrators-group membership changes |
| Process execution | Sysmon 1 | Examine selected LOLBin activity |
| Network activity | Sysmon 3 | Review connections by process |
| DNS activity | Sysmon 22 | Examine DNS queries by process |

## Detection: repeated failed logons

**Rule:** 3 or more failed logons for the same account within 15 minutes.

| Setting | Configuration |
|---|---|
| Event | 4625 |
| Grouping | Failed account |
| Threshold | 3 or more failures |
| Search window | Last 15 minutes |
| Schedule | Every 15 minutes |
| Throttle | 30 minutes per `failed_account` |
| Severity | Medium |
| Action | Add to Triggered Alerts |

### Validation

The detection was tested using `commands/trigger-alert-test.ps1`.

- Generated four failed authentication attempts.
- Targeted the nonexistent account `labfakeuser`.
- The scheduled alert successfully triggered.
- The alert result showed 4 failures.
- Returned status: `0xC0000064` (account does not exist).

The test deliberately targeted a nonexistent account to avoid repeatedly failing authentication against a real account and reducing the risk of account lockout.

**Important:** a triggered alert confirms that the detection logic worked under the test conditions. It does not establish malicious activity.

## Dashboard: Windows Investigation

Three panels provide a consolidated view of authentication failures.

| Panel | Purpose |
|---|---|
| Failed logons over time | Identify authentication failure patterns |
| Failed logons by account | Identify accounts generating failures |
| Failed logons by status | Examine authentication failure reasons |

- Global time range: Last 30 days.
- Dashboard format: Dashboard Studio.
- Export: `splunk/dashboard.json`.

The account panel groups failures by the last extracted value of `Nombre_de_cuenta`, matching the account-grouping logic used in Search 01.

**Evidence note:** the archived dashboard screenshot predates the latest account-panel correction. Re-import `dashboard.json` or update the panel in Splunk, then capture a new three-panel screenshot before submission.

## Honest findings

- Windows event fields were extracted using Spanish-localized field names. English field-name assumptions returned no results.
- Searches 03 and 07 use `rex` patterns matching Spanish event-message text. These patterns may require adjustment on systems using another Windows display language.
- Search 07 identifies Administrators-group additions (4732), but its results still need to be rerun and captured as archived evidence.
- The seven-day Sysmon searches cross the configuration change applied on 2026-11-22 at 16:21 UTC. Historical results therefore include telemetry from both configurations.
- Correlation to Logon ID `0x27457` remains unverified in the archived evidence.
- The alert's 15-minute search interval and 15-minute scheduling interval can introduce timing gaps. A production detection should account for scheduling delays, execution time and overlapping search windows.
- The dashboard's original screenshot does not reflect the latest account-panel grouping correction.

These findings represent lab observations, not confirmed malicious activity. Failed logons, process execution, network connections and administrative changes can also result from normal user activity, troubleshooting, services and scheduled tasks.

## Files

- `report.md`: full investigation report.
- `splunk/01-failed-logons.spl`: failed logons summarized by account.
- `splunk/02-logon-type-breakdown.spl`: successful and failed logons by logon type.
- `splunk/03-new-user-created.spl`: local account creation (4720).
- `splunk/04-lolbin-process-creation.spl`: selected LOLBin process activity.
- `splunk/05-sysmon-network-by-process.spl`: network connections by process.
- `splunk/06-dns-queries.spl`: DNS queries by process.
- `splunk/07-admin-group-changes.spl`: Administrators-group additions (4732).
- `splunk/alert-failed-logons.spl`: scheduled failed-logon detection.
- `splunk/dashboard.json`: three-panel Dashboard Studio definition.
- `commands/trigger-alert-test.ps1`: controlled alert-validation script.

## Screenshots

The `screenshots/` directory contains the investigation, detection and dashboard evidence.

Key evidence:

- `2026-11-23_project04_dashboard-failed-logons.png`: final three-panel dashboard capture (refresh after the account-panel correction).
- Alert configuration screenshot: scheduled search, threshold, throttle and severity.
- Alert results screenshot: four failed logons for `labfakeuser`.
- Triggered alert screenshot: successful alert execution.
- Search screenshots: authentication, account creation, process, network, DNS and group-change investigations.
- Field-validation screenshots: extracted Spanish-localized Windows event fields.

The alert configuration screenshot was captured before the alert fired. The later triggered-alert screenshot provides evidence of successful validation.

## Learning takeaway

A SOC investigation is not simply about finding suspicious events. It is about understanding the telemetry, validating the extracted fields, identifying meaningful patterns, and explaining what the evidence actually proves.

This project demonstrates a complete investigation workflow: Windows event collection, SPL-based analysis, account and authentication investigation, scheduled detection, controlled alert validation and dashboard reporting.

**Key lesson:** detection quality depends on both the logic and the reliability of the underlying telemetry. A successful alert is only the beginning of an investigation.
