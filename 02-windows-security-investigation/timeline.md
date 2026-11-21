# Project 02 timeline (UTC)

Source: Splunk search in `splunk/searches.spl` (46 events), cross-checked against my PowerShell queries. Splunk displayed times in +0200 (Helsinki). Every time below is converted to UTC by subtracting 2 hours, and the converted times match the PowerShell UTC output (for example 4726 at 11:10:58 UTC and the 4624 pair at 10:36:02 UTC).

Labels: Observed (seen in an event), Interpretation (my reading of it), Hypothesis (plausible, not verified), Unknown (not explained).

| UTC | Event IDs | Account | Logon type | Source process | Meaning | Label |
|---|---|---|---|---|---|---|
| 20/11 13:05:15 | 4720, 4722, 4724, 4738 x2 | labuser (created by my admin account) | - | - | Step 1. Account created disabled with "password not required", then enabled, password set and attributes updated. One command produced five events. | Observed |
| 20/11 13:05:43 | 4732 | labuser (shown by SID only) | - | - | Step 2. Added to the local Administrators group (S-1-5-32-544). | Observed |
| 20/11 13:08:13 | 4648, 4776, 4625 | labfakeuser | 3 | NtLmSsp (NTLM network logon to my own machine) | One failed validation, SubStatus 0xC0000064 (user name does not exist). It is not in my command history. | Observed; cause Unknown |
| 20/11 13:08:21 to 13:08:25 | 4648, 4776, 4625 x3 | labfakeuser | 3 | NtLmSsp | Three attempts two seconds apart: my loop with fake passwords. Same SubStatus 0xC0000064. | Observed; link to my loop is Interpretation |
| 20/11 13:11:43 | 4648, 4776, 4625 | labfakeuser | 3 | NtLmSsp | One more failed validation, SubStatus 0xC0000064. It is not in my command history. | Observed; cause Unknown |
| 20/11 13:12:54 | 4733 | labuser (shown by SID only) | - | - | Removed from Administrators. | Observed |
| 20/11 14:00:43 | 4798 | labuser | - | LogonUI.exe (SYSTEM) | The sign-in screen listed the local group membership of labuser. I did not trigger this on purpose. | Observed; cause Hypothesis (sign-in screen enumerating local accounts) |
| 21/11 10:21 to 10:28 | 4738 x4 (not in this export) | my own account, changed by the machine account | - | - | Seen in PowerShell only. I cannot explain it yet; it falls around my own sign-in that morning (to check against 4624). | Unknown |
| 21/11 10:22:06 | 4798 | labuser | - | LogonUI.exe (SYSTEM) | Same as the 20/11 14:00:43 row. | Observed; cause Hypothesis |
| 21/11 10:34:34 | 4732 | labuser (shown by SID only) | - | - | Added to Administrators a second time, so the split-token test could work. | Observed |
| 21/11 10:34:50 | 4688 | my admin account | - | runas.exe (from PowerShell) | `runas /user:labuser cmd` logged with its command line. No password appears in it. | Observed |
| 21/11 10:35:03, 10:35:15, 10:35:26 | 4625, 4776 (x3 each) | labuser | 2 | svchost.exe (logon process seclogo) | Wrong password, SubStatus 0xC000006A (user exists, password wrong). | Observed |
| 21/11 10:35:08, 10:35:20, 10:35:52 | 4688 x3 | my admin account | - | runas.exe | Three more runas runs: four in total, three with a wrong password and one with the correct one. | Observed |
| 21/11 10:36:02 | 4776 (0x0), 4648, 4672, 4624 x2 | labuser | 2 | svchost.exe | Successful logon with special privileges assigned. The two 4624 events point at each other through the linked logon ID: one has "elevated token: Yes", the other "No". | Observed; the split-token explanation is Interpretation |
| 21/11 10:36:05 | 4688 x2 | labuser | - | cmd.exe, conhost.exe (parent runas.exe) | The shell started under labuser with a limited token. | Observed; reading is Interpretation |
| 21/11 10:36:36 | 4733 | labuser (shown by SID only) | - | - | Removed from Administrators again. | Observed |
| 21/11 10:37:22 | 4634 x2 | labuser | 2 | - | Both linked logon sessions ended after exit. | Observed |
| 21/11 11:10:58 | 4726 | labuser | - | - | Step 6. Account deleted. | Observed |

## SubStatus comparison (forgotten password vs guessing)

| Account | Exists? | Status | SubStatus | Reading |
|---|---|---|---|---|
| labfakeuser | No | 0xC000006D | 0xC0000064 | The user name does not exist. |
| labuser | Yes | 0xC000006D | 0xC000006A | The user name exists and the password is wrong. |

Observed: the SubStatus differs for the same kind of failed logon.

Interpretation: a burst of 0xC0000064 across many names points to user-name guessing. Repeated 0xC000006A against one real name points to password guessing on a valid account. One or two 0xC000006A followed by a success, like mine at 10:36:02 UTC, looks like a forgotten password.

## Notes
- The raw export contains my Windows account name and SIDs, so I do not publish it.
- The leftover profile folder of labuser was removed with Remove-CimInstance after the account was deleted.