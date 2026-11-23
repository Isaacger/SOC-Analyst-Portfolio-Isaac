Project 04 — Windows Security Investigation with Splunk
1. Summary
This project used Splunk Cloud to investigate Windows Security and Sysmon telemetry, build repeatable searches, configure a scheduled failed-logon alert, and create a three-panel dashboard. The controlled alert test generated four failed logons for a nonexistent account and successfully triggered the alert.
2. Scope
The investigation covered:
- Failed and successful logons (4625 and 4624)
- Local account creation (4720)
- Administrators-group membership changes (4732)
- Sysmon process creation (Event 1)
- Sysmon network connections (Event 3)
- Sysmon DNS queries (Event 22)
This was a local learning lab. The findings should not be treated as proof of malicious activity.
3. Environment
- Endpoint: Windows 10 Home Single Language, 22H2, 64-bit, build 19045.
- SIEM: Splunk Cloud.
- Index used in the saved searches: main.
- Windows event fields are extracted in Spanish on this endpoint.
4. Method
Saved SPL searches were used to filter event IDs, extract or normalize fields, aggregate activity, and sort results. The investigation used timestamps, account names, SIDs, status/substatus, source information, and logon session identifiers to pivot between events.
5. Failed-logon review
Search 01 summarized EventCode 4625 by account. The archived search screenshot showed:
- labfakeuser: 5 failures in the historical result set, between 2026-11-20 15:08:13 and 15:11:43.
- labuser: 3 failures in the historical result set, between 2026-11-21 12:35:03 and 12:35:26.
These are observations in the indexed lab data. A failed logon may result from a typo, expired stored credentials, a service, or other benign causes; the event count alone does not establish password guessing.
6. Account creation
Search 03 identified a 4720 account-creation event:
- Account created: labuser
- Event time: 2026-11-20 15:05:15 (as shown in the saved search screenshot)
- The new account SID was extracted from the Spanish event message.
The reviewed SPL now includes created_by in the output table as well as _time, created_account, and new_sid. The archived screenshot predates this output-field correction; rerun the saved search in Splunk if you want the live result table to match the reviewed SPL.
7. Administrators-group changes
Search 07 filtered EventCode 4732 using the built-in Administrators group SID S-1-5-32-544, then extracted the member SID, actor SID, and actor Logon ID from the Spanish event message.

The investigation notes record the labuser SID (ending -1002) added to Administrators by the dearc SID (ending -1001), with actor Logon ID 0x27457. The first recorded group-add event was at 2026-11-20 15:05:43, approximately 28 seconds after the account-creation event at 15:05:15. The notes also record a second group-add event on 2026-11-21 12:34:34 with the same Logon ID.

The archived screenshots do not include a result screenshot for Search 07, so these entries rest on the notes alone. A logon session ID normally does not persist across two days, so the repeated Logon ID should be verified in Splunk against the raw 4732 events before this finding is relied on. The timing is a useful lead, but it does not by itself prove malicious intent.
8. Sysmon telemetry
Searches 04–06 examined selected LOLBin process creation, network connections by process, and DNS queries by process. The SPL files document common benign sources of noise, including browsers, system services, updates, scheduled tasks, and the Splunk forwarder.

The 7-day searches span a Sysmon configuration change made on 2026-11-22 16:21 UTC. Therefore, the historical result set mixes events collected under the previous and updated configurations.
9. Alert design
Alert name: Failed logons: 3+ in 15 minutes
- Detection: EventCode 4625 grouped by failed_account.
- Threshold: failures >= 3.
- Schedule: every 15 minutes (*/15 * * * *).
- Search window: last 15 minutes.
- Trigger: number of results greater than zero, per result.
- Throttle: 30 minutes per failed_account.
- Severity: Medium.
- Action: Add to Triggered Alerts.
The schedule interval and search window are both 15 minutes. This is intended to cover consecutive time windows without leaving a gap between scheduled runs, subject to the alert's actual scheduling and execution behavior.
10. Controlled alert validation
The script commands/trigger-alert-test.ps1 attempted four network logons using the nonexistent account labfakeuser, with an incorrect password, and recorded the local test time.

The saved search-results screenshot showed:
- 4 matching EventCode 4625 events
- Account: labfakeuser
- Substatus: 0xC0000064
The alert was recorded in Triggered Alerts at 2026-11-23 13:31:32 EET. This confirms the alert fired during the controlled test. The script targets a nonexistent account to avoid deliberately failing logons against a real account.
11. Dashboard
Dashboard title: Windows Investigation
Global time range: Last 30 days

The final dashboard, as shown in the saved screenshot, contains:
1. Failed logons over time
2. Failed logons by account
3. Failed logons by status
The final three-panel dashboard screenshot is included as screenshots/2026-11-23_project04_dashboard-failed-logons.png. It shows the 30-day time range, with failed logons by account and by status both populated.
12. Limitations
- Spanish field names and message text make some SPL language-specific.
- The rex patterns in Searches 03 and 07 are written for Spanish event messages.
- Sysmon historical searches span a configuration change.
- The Sysmon Event 1 correlation to Logon ID 0x27457 was not confirmed in the archived project evidence; it should be recorded as unverified rather than claimed as a successful link.
- The dashboard's account panel now groups by the failed account (last value of Nombre_de_cuenta), matching Search 01. The screenshot predates this change and should be re-captured after re-importing dashboard.json.
- The dashboard's default global time range is Last 30 days (-30d@d,now), matching the screenshot.
13. Conclusion and next improvement
The project demonstrates a repeatable workflow: search Windows events, pivot from failed logons to account creation and group changes, configure an alert, validate it with a controlled test, and summarize the results in a dashboard.

The final dashboard screenshot and its exported definition (splunk/dashboard.json) are included. A further detection improvement would correlate recent account creation with subsequent Administrators-group membership changes, while retaining analyst review for legitimate administration.