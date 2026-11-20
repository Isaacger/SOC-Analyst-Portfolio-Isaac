# Microsoft Sentinel feasibility (Item 07)

**Decision:** Sentinel is not used in Project 01. Hands-on Sentinel moves to Project 05, using an Azure Windows Server VM that can be onboarded the supported way.

## Question

Can Microsoft Sentinel collect Security and Sysmon events from the Lenovo (Windows 10 Home) in this project?

## Facts

- Microsoft's agent for Windows client devices (the Azure Monitor Agent client installer) requires the device to be **Microsoft Entra joined or hybrid joined**. Windows 10 Home cannot be Entra joined, so the Lenovo cannot use the standard collection path.
- Sentinel offers a **31-day free trial**, covering up to **10 GB/day** of ingestion. Usage after the trial or above the limit is billed.
- Microsoft Sentinel leaves the Azure portal on **31 March 2027** and will be managed only in the **Microsoft Defender portal**. A lab built now should target the Defender portal.

## Options considered

| Option | Works with this laptop? | Effort | Verdict |
|---|---|---|---|
| Azure Monitor Agent on the Lenovo | No: needs Entra join, which Home edition lacks | — | Rejected |
| Windows Server VM in Azure, onboarded with the Azure Monitor Agent | Yes: the supported path for servers | Medium | **Chosen, for Project 05** |
| Custom ingestion through the Logs Ingestion API | Possible | High: custom tables and scripting | Not worth it for a portfolio lab |

## Cost controls for Project 05

- Start the trial only when the VM is ready, so the 31 days are used.
- Collect only Security and Sysmon events, as in Project 01.
- Set a daily ingestion cap, and delete the VM and workspace when the project is finished.

## My view

I agree with the decision. Forcing an unsupported path on Windows 10 Home would cost hours and teach me less than a supported setup. Project 01 already proves the pipeline concept with Splunk Cloud. In a SOC, checking that a connector is supported **before** deploying it is part of the job.

## Sources

- [Install the Azure Monitor Agent on Windows client devices](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-windows-client)
- [Microsoft Sentinel: plan costs and understand pricing and billing](https://learn.microsoft.com/azure/sentinel/billing)
- [Microsoft unified security operations: what's new](https://learn.microsoft.com/unified-secops/whats-new)
