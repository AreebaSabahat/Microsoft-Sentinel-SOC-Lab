# Microsoft-Sentinel-SOC-Lab
Microsoft Sentinel SOC lab demonstrating Windows Event ID 4625 detection, KQL investigation, incident analysis and resolution.
# Microsoft Sentinel SOC Lab – Windows Failed Logon Detection & Investigation

## 📌 Project Overview

This project demonstrates a practical SOC investigation using Microsoft Sentinel and Microsoft Defender.

I created a controlled Windows failed-logon scenario, collected the security events, detected multiple failed authentication attempts using Windows Security Event ID 4625, investigated the activity using KQL, reviewed the generated security incident, and documented the investigation and resolution.

The purpose of this lab was to practise the workflow of a SOC Analyst from detection through investigation and incident closure.

---

## 🛠️ Technologies & Skills Used

- Microsoft Sentinel
- Microsoft Defender
- Windows Security Event Logs
- Kusto Query Language (KQL)
- Event ID 4625 – Failed Logon
- SIEM monitoring
- Alert investigation
- Incident triage
- Log analysis
- Incident documentation and resolution

---

## 🔎 Investigation Scenario

Multiple unsuccessful Windows login attempts were generated in a controlled lab environment.

Windows recorded these attempts as:

*Event ID 4625 – An account failed to log on*

The events were ingested into the SIEM and investigated to determine:

- Which account generated the failed authentication attempts
- Which endpoint was involved
- How many failed attempts occurred
- Whether the activity indicated malicious behaviour
- How the incident should be classified and resolved

---

## 1️⃣ Incident Detection

Microsoft Sentinel generated an incident for multiple failed Windows logon attempts.

![Incident Overview](1.Incident%20Overview%20.png)

---

## 2️⃣ Event ID 4625 Analysis

I examined the underlying Windows Security event to understand the authentication failure and relevant event details.

![Event ID 4625 Analysis](2.Windows%20Event%20ID%204625%20Analysis.png)

---

## 3️⃣ KQL – Identify Failed Logons

I used KQL to search for Windows Security Event ID 4625.

kql
SecurityEvent
| where EventID == 4625


This returned the failed authentication events for further investigation.

![Failed Logon Results](3.KQL%20Event%204625%20failed%20logon%20Results.png)

---

## 4️⃣ KQL – Investigate Relevant Fields

I refined the query to focus on useful investigation fields such as the account, computer, IP address, logon type and activity.

kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, LogonType, Activity
| order by TimeGenerated desc


This made it easier to review the failed authentication attempts and identify the affected endpoint/account.

![KQL Investigation](4.KQL%20Investigation.png)

---

## 5️⃣ KQL – Aggregate Failed Attempts

I then aggregated the events to identify accounts/endpoints with repeated failed authentication attempts.

kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account, Computer
| sort by FailedAttempts desc


This is useful during SOC triage because repeated authentication failures can indicate password guessing, user error, misconfiguration or potentially malicious authentication activity.

![Failed Logon Aggregation](5.KQL%20Failed%20Logon%20Aggregation.png)

---

## 6️⃣ Investigation & Resolution

After reviewing the events and related activity, I determined that the failed logons were generated as part of my controlled security lab rather than an actual compromise.

The incident was therefore resolved as *expected/confirmed lab activity*, with no additional malicious activity identified.

![Incident Resolution](6.%20Sentinel%20Incident%20Investigated%20and%20Resolved%20.png)

---

## 📊 Investigation Workflow

*Generate failed authentication attempts → Collect Windows Security logs → Detect Event ID 4625 → Investigate with KQL → Analyse account and endpoint activity → Review Sentinel incident → Classify and resolve*

---

## 🎯 What I Learned

Through this lab I gained hands-on experience with:

- Investigating authentication events in a SIEM
- Understanding Windows Event ID 4625
- Writing and refining KQL queries
- Filtering relevant security-event fields
- Aggregating failed authentication attempts
- Investigating Microsoft Sentinel incidents
- Distinguishing controlled/expected activity from suspicious activity
- Documenting and resolving a security incident

---

## 🔐 SOC Relevance

Failed authentication monitoring is an important SOC use case. A SOC analyst should be able to distinguish normal user mistakes or expected activity from patterns that may warrant further investigation, such as password spraying, brute-force attempts or compromised credentials.
This lab demonstrates a basic end-to-end SOC workflow using Microsoft Sentinel: *detection, triage, investigation, analysis and resolution*.

## 🛡️ Key Skills Demonstrated

- Microsoft Sentinel
- Microsoft Defender
- Kusto Query Language (KQL)
- Windows Security Event ID 4625 Analysis
- Failed Logon Detection & Investigation
- Security Incident Triage
- Authentication Log Analysis
- Event Correlation
- SOC Investigation Workflow
- Incident Investigation & Resolution




