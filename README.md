# Northgate Retail - Supplier Portal to POS Data Exfiltration Investigation

**Investigation Team:** Elay Adar (Case Lead), Yossef (Identity & Access), Gavriel (Data & Impact)

> Elay Adar led this investigation end to end - scoping the case, owning the executive summary and incident classification, and compiling the final report and MITRE ATT&CK mapping.

---

## 1. Executive Summary

Northgate Retail Ltd suffered a supply-chain intrusion in which an external actor exploited the public supplier portal to gain a foothold, escalated to administrative access, and deployed automated tooling across 34 of 42 point-of-sale terminals. Between August 16 and August 19, 2026, the actor staged roughly 430 MB of POS transaction logs on an internal staging server and exfiltrated 180 MB of that data to an external host before attempting to erase the evidence. At the time of reporting the incident was not fully contained - automated data collection was still observed after the anti-forensic activity concluded, and the initial access vector remained unremediated.

---

## 2. Incident Metadata

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **Status** | Escalated - Not Fully Contained |
| **Category** | Data Exfiltration (Supply-Chain to POS Estate) |
| **Target Asset(s)** | SRV-VEND-APP, SRV-FILE-HQ, SRV-POSMGT (critical), SRV-STAGE-01, 34 of 42 branch POS terminals |
| **Accounts Used** | a.mizrahi (Admin, IT-Infra), r.stern (Standard, Payments) - both used exclusively from SRV-VEND-APP |
| **MITRE ATT&CK Mapping** | TA0001 Initial Access, TA0043 Reconnaissance, TA0002 Execution, TA0003/TA0004 Persistence & Privilege Escalation, TA0008 Lateral Movement, TA0006 Credential Access, TA0007 Discovery, TA0009 Collection, TA0005 Defense Evasion, TA0010/TA0011 Exfiltration & Command and Control |

---

## 3. Environment & Log Sources

**SIEM Platform:** Splunk (`index=northgate`)

| Log Source | Sourcetype | Purpose in Investigation |
|---|---|---|
| Windows Event Logs | `winevent` | Logon events (4624, 4672), process creation (4688), scheduled task create/delete (4698), SMB share access (5140) |
| Web Server Logs | `weblog` | Supplier portal access, API enumeration requests |
| File Access Audit | `fileaudit` | Staging, write, read and delete activity on file servers |
| Proxy Logs | `proxy` | Outbound HTTP requests, verdicts, destination hosts, bytes transferred |
| Cloud Audit Logs | `cloudaudit` | Internal file share link creation |
| Backup Job Logs | `backup` | Job status and backup coverage by target |
| Asset Inventory | `assets.csv` (lookup) | Hostname, owner, EDR coverage, criticality rating |

---

## Repository Contents

| File / Folder | Description |
|---|---|
| `README.md` | This file |
| `IR_Report.pdf` | Full written investigation report |
| `logs/` | Raw CSV log exports used during analysis |
| `Final_Presentation` | Stakeholder-facing summary deck |
| `ai-verification-log` | Record of where AI assistance was used, verified, corrected, or rejected during this investigation |
