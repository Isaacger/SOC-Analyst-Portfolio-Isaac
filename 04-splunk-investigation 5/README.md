Project 04 — Windows Security Investigation with Splunk
Overview
A hands-on Windows security investigation using Splunk Cloud, Windows Security events, and Sysmon telemetry. The project practices event searching, field extraction, account and group-change investigation, alerting, and dashboarding.
Investigation objectives
- Review failed logons and identify account, time, source, logon type, and status.
- Examine logon types and selected process/network/DNS telemetry.
- Identify account creation and Administrators-group membership changes.
- Build and test a scheduled alert for repeated failed logons.
- Present the findings in a three-panel dashboard.
Environment and data
- Windows endpoint: Windows 10 Home Single Language, 22H2, 64-bit (build 19045).
- SIEM: Splunk Cloud.
- Data: Windows Security events and Sysmon Operational events.
- Security event IDs used: 4624, 4625, 4720, 4732.
- Sysmon event IDs used: 1 (process creation), 3 (network connection), 22 (DNS query).
Saved searches
File	Purpose
splunk/01-failed-logons.spl	Failed logons summarized by account
splunk/02-logon-type-breakdown.spl	Successful/failed logons by logon type
splunk/03-new-user-created.spl	New local account creation (4720)
splunk/04-lolbin-process-creation.spl	Selected LOLBin process activity
splunk/05-sysmon-network-by-process.spl	Sysmon network connections by process
splunk/06-dns-queries.spl	Sysmon DNS queries by process
splunk/07-admin-group-changes.spl	Administrators-group additions (4732)
splunk/alert-failed-logons.spl	Alert search for repeated failed logons


Alert
Failed logons: 3+ in 15 minutes
- Search: EventCode 4625, grouped by failed account.
- Threshold: 3 or more failures for one account in the 15-minute search window.
- Schedule: every 15 minutes; last 15 minutes searched.
- Throttle: 30 minutes per failed_account.
- Severity: Medium.
- Action: Add to Triggered Alerts.
- Validation: a controlled test produced four failures for the nonexistent account labfakeuser; the alert fired and the result showed 4 failures with status 0xC0000064.
The test script is commands/trigger-alert-test.ps1. It targets a nonexistent account and does not intentionally use a real account, reducing the risk of account lockout.
Dashboard
Dashboard title: Windows Investigation
Global time range: Last 30 days

Panels:
1. Failed logons over time
2. Failed logons by account
3. Failed logons by status
The final three-panel dashboard screenshot is included as screenshots/2026-11-23_project04_dashboard-failed-logons.png. It shows the saved dashboard with the 30-day time range. An earlier two-panel draft capture is not included in this package and is not the final dashboard evidence.
Evidence
The screenshots/ folder contains search screenshots, alert configuration/results/triggered-alert evidence, field validation, and the final three-panel dashboard screenshot. The alert configuration screenshot was taken before the alert fired; the later alert-triggered screenshot records the successful trigger.
Limitations and cautions
- The Windows event field names are localized in Spanish. SPL uses the actual extracted field names; English field-name guesses returned no data.
- Search 03 and 07 use rex patterns for Spanish event-message text and may need adjustment on systems using another event language.
- The 7-day Sysmon searches span the configuration change made on 2026-11-22 16:21 UTC; historical results include telemetry from both configurations.
- Sysmon correlation to Logon ID 0x27457 is not confirmed in the archived evidence and is recorded as unverified.
- The Search 07 finding relies on the investigation notes; no archived screenshot shows its results. Re-run it in Splunk and capture the result before submitting.
- The dashboard definition is exported to splunk/dashboard.json (Dashboard Studio JSON, title "Windows Investigation", three panels).
- The account panel now groups by the failed account (last value of Nombre_de_cuenta), the same logic as Search 01. The dashboard screenshot predates this change: re-import dashboard.json or edit that panel in Splunk, then re-capture the screenshot with the same filename.
- The dashboard's default global time range is Last 30 days (-30d@d,now), matching the screenshot and this README.
- These observations are lab findings, not proof of malicious activity. Normal administrative actions, user errors, services, and scheduled tasks can produce similar events.
Reproduce
1. In Splunk, run the saved SPL files against the configured index and time range.
2. Review the field names in the raw event before writing field-dependent SPL.
3. Run the controlled test only in the lab and only if you want to revalidate the alert.
4. Confirm the alert appears under Triggered Alerts.
5. Open the saved dashboard and verify all three panels have data.
6. The final dashboard screenshot is already included. If you later change the dashboard, replace it with a new capture using the same filename.
Learning takeaway
A useful investigation links events by stable identifiers and context—such as account SID, event time, and logon session ID—rather than relying only on account names. Correlation increases confidence, but temporal proximity or a shared session ID alone does not prove malicious intent.