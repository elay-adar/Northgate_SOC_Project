# Northgate Retail - Supplier Portal to POS Data Exfiltration Investigation

**Investigation Team:** Elay Adar (Case Lead), Yossef (Identity & Access), Gavriel (Data & Impact)

---

## 1. Executive Summary

Northgate Retail Ltd suffered a supply-chain intrusion in which an external actor logged in to the public supplier portal and gained a foothold on an internal application server, escalated to administrative access, and deployed automated tooling across 34 of 42 point-of-sale terminals. Between August 16 and August 19, 2026, the actor staged roughly 430 MB of POS log files (`*.log.1`) on an internal staging server and exfiltrated 180 MB of that data to an external host before attempting to erase the evidence. At the time of reporting the incident was not fully contained - automated data collection was still observed after the anti-forensic activity concluded, and the initial access vector remained unremediated.

---

## 2. Incident Metadata

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **Status** | Escalated - Not Fully Contained |
| **Category** | Data Exfiltration (Supply-Chain to POS Estate) |
| **Target Asset(s)** | SRV-VEND-APP, SRV-FILE-HQ, SRV-POSMGT (critical), SRV-STAGE-01, 34 of 42 branch POS terminals |
| **Accounts Used** | a.mizrahi (Admin, IT-Infra), r.stern (Standard, Payments) - both logged on from SRV-VEND-APP; r.stern's account wrote the staged files from the 34 POS terminals |
| **MITRE ATT&CK Mapping** | TA0001 Initial Access, TA0043 Reconnaissance, TA0002 Execution, TA0003/TA0004 Persistence & Privilege Escalation, TA0008 Lateral Movement, TA0006 Credential Access, TA0007 Discovery, TA0009 Collection, TA0005 Defense Evasion, TA0010/TA0011 Exfiltration & Command and Control |

---

## 3. Attack Timeline

Chronology of the incident as reconstructed in the investigation report (section 4). Times are UTC; rows marked "converted from UTC+3" are Windows event log (winevent) entries, as in the report. Each entry links to the query behind it.

| Time (UTC) | Source | Host / Actor | What happened | Query |
|---|---|---|---|---|
| 2026-08-09 07:12:00 | weblog | `WEB-SUPPLIER` / `77.124.66.19` | Successful `POST /supplier/login`. The account cannot be identified: weblog has no user field. | [#1](queries/timeline.md#query-1) |
| 2026-08-09 07:40:01 to 07:47:54 | weblog | `WEB-SUPPLIER` / `77.124.66.19` | 44 requests to `/supplier/api/v2/inventory?branch=B<nn>` for branches B01-B38 at fixed 11-second intervals, all HTTP 200. | [#1](queries/timeline.md#query-1) |
| 2026-08-10 23:04:01 <br>(converted from UTC+3) | winevent 4688 | `SRV-VEND-APP` / `IIS APPPOOL\supplier` | `w3wp.exe` spawned `cmd.exe` running `whoami`, `ipconfig /all` and `net view`. | [#2](queries/timeline.md#query-2) |
| 2026-08-10 23:31:01 <br>(converted from UTC+3) | winevent 4698 | `SRV-VEND-APP` / `IIS APPPOOL\supplier` | Scheduled task `NGSupplierSync` created to run every 4 hours, with no program specified. Command: `schtasks /create /tn NGSupplierSync /sc hourly /mo 4`. | [#2](queries/timeline.md#query-2) |
| 2026-08-11 02:15:01 <br>(converted from UTC+3) | winevent 4624 + 4672 | `SRV-FILE-HQ` / `a.mizrahi` from `SRV-VEND-APP` | `a.mizrahi` logon (type 3) to `SRV-FILE-HQ` from `SRV-VEND-APP`, with special privileges (4672). | [#3](queries/timeline.md#query-3) |
| 2026-08-12 22:00:00 to 2026-08-15 22:46:12 <br>(converted from UTC+3) | winevent 5140 | `SRV-FILE-HQ` / `a.mizrahi` from `SRV-VEND-APP` | 40 share-access events across 6 distinct shared folders; no file activity recorded. | [#12](queries/timeline.md#query-12), [#13](queries/timeline.md#query-13) |
| 2026-08-15 21:46:59 <br>(converted from UTC+3) | winevent 4624 | `SRV-POSMGT` / `r.stern` from `SRV-VEND-APP` | `r.stern` logon (type 3) to `SRV-POSMGT` from `SRV-VEND-APP`; all 188 earlier `r.stern` logons in 90 days came from `WKS-PAY-02`. | [#5](queries/timeline.md#query-5) |
| 2026-08-16 01:19:59 to 01:29:20 <br>(converted from UTC+3) | winevent 4688 | 34 x POS / `r.stern` | `ngpos-cfg.exe /apply /src \\SRV-POSMGT\cfg\pos-profile.dat` got executed on 34 POS machines at a fixed 17-second interval, consistent with a scripted rollout. | [#7](queries/timeline.md#query-7) |
| 2026-08-16 03:00:00 | fileaudit | `SRV-STAGE-01` / `r.stern` | Collection begins on `\\SRV-STAGE-01\temp`. | [#8](queries/timeline.md#query-8) |
| 2026-08-16 to 2026-08-19, daily 03:00:00-22:34:19 | fileaudit | `SRV-STAGE-01` / `r.stern` from 34 x POS | `r.stern` wrote 2,850 distinct files (~430 MB) from 34 POS machines to `SRV-STAGE-01` between 2026-08-16 and 2026-08-19, averaging ~84 files per machine. | [#8](queries/timeline.md#query-8) |
| 2026-08-19 00:10:01 <br>(converted from UTC+3) | winevent 4688 | `SRV-STAGE-01` / `r.stern` | Archive created from the 2,138 files (322.53 MiB) staged at that time. Command: `ngarch.exe -a -q -o D:\temp\ngsync-0819.dat \\SRV-STAGE-01\temp\*.log.1`. | [#7](queries/timeline.md#query-7), [#6](queries/timeline.md#query-6) |
| 2026-08-19 02:55:01 to 04:10:01 | proxy | `SRV-STAGE-01` / unknown | 6 POSTs to `edge-sync-eu.net`, 180 MiB in total, 15 minutes apart, all allowed. | [#9](queries/timeline.md#query-9) |
| 2026-08-19 04:30:00 <br>(converted from UTC+3) | winevent 4698 | `SRV-VEND-APP` / `IIS APPPOOL\supplier` | Scheduled task `NGSupplierSync` deleted (logged under EventCode 4698; the standard Windows ID for task deletion is 4699). Command: `schtasks /delete /tn NGSupplierSync /f`. | [#2](queries/timeline.md#query-2) |
| 2026-08-19 04:30:00 to 05:07:38 | fileaudit | `SRV-STAGE-01` / `r.stern` | 2,510 files deleted in 37m 38s, while 22 new files were written in the same window. | [#10](queries/timeline.md#query-10), [#11](queries/timeline.md#query-11) |
| 2026-08-19 22:34:19 | fileaudit | `SRV-STAGE-01` / `r.stern` | Last staged write; 340 files (53,820,040 bytes) from all 34 terminals were never deleted. | [#14](queries/timeline.md#query-14) |

---

## 4. Environment & Log Sources

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

## 5. MITRE ATT&CK Mapping

Technique-level mapping of the attack chain, with the detection status recorded in the investigation report (section 8). The `a.mizrahi` and `r.stern` account takeovers are the stages marked as not detected.

| Stage | Tactic | Technique | Detected | Source |
|---|---|---|---|---|
| `POST /supplier/login` | Initial Access (TA0001) | Valid Accounts (T1078) - suspected; the account was not identified | yes | weblog |
| 44 API requests enumerating `/inventory` | Reconnaissance (TA0043) | Active Scanning (T1595) - sequential branch IDs B01-B38 | yes | weblog |
| `w3wp.exe` spawns `cmd.exe` and runs `whoami`, `ipconfig /all`, `net view` | Execution (TA0002), Discovery (TA0007) | Command and Scripting Interpreter: Windows Command Shell (T1059.003)<br>System Owner/User Discovery (T1033)<br>System Network Configuration Discovery (T1016)<br>Network Share Discovery (T1135)<br>Network Service Discovery (T1046) | yes | winevent |
| Scheduled task creation | Persistence (TA0003), Privilege Escalation (TA0004) | Scheduled Task/Job: Scheduled Task (T1053.005) | yes | winevent |
| Account takeover of `a.mizrahi` on SRV-VEND-APP, admin credentials used from the compromised host | Privilege Escalation (TA0004), Lateral Movement (TA0008), Credential Access (TA0006) | Valid Accounts: Domain Accounts (T1078.002)<br>Use Alternate Authentication Material (T1550)<br>OS Credential Dumping (T1003) | no | - |
| `a.mizrahi` logon type 3 from SRV-VEND-APP | Lateral Movement (TA0008), Defense Evasion (TA0005) | Remote Services (T1021)<br>Valid Accounts: Domain Accounts (T1078.002) | yes | winevent |
| Automated network share enumeration (event 5140) | Discovery (TA0007) | Network Share Discovery (T1135) | yes | winevent |
| Account takeover of `r.stern` on SRV-VEND-APP | Privilege Escalation (TA0004), Lateral Movement (TA0008), Credential Access (TA0006) | Valid Accounts: Domain Accounts (T1078.002)<br>Use Alternate Authentication Material (T1550)<br>OS Credential Dumping (T1003) | no | - |
| `r.stern` logon type 3 from SRV-VEND-APP | Lateral Movement (TA0008) | Remote Services: SMB/Windows Admin Shares (T1021.002)<br>Valid Accounts: Domain Accounts (T1078.002) | yes | winevent |
| Automated POS profile deployment via `ngpos-cfg.exe` | Execution (TA0002) | Command and Scripting Interpreter (T1059)<br>System Services: Service Execution (T1569.002) - possible; the remote launch method was not logged | yes | winevent |
| Data collection on `\\SRV-STAGE-01\temp` in `.log.1` format | Collection (TA0009) | Data Staged: Remote Data Staging (T1074.002) | yes | fileaudit |
| Archiving `*.log.1` files into `ngsync-0819.dat` | Collection (TA0009), Defense Evasion (TA0005) | Archive Collected Data: Archive via Utility (T1560.001) | yes | winevent |
| 6 POSTs to `edge-sync-eu.net` | Exfiltration (TA0010), Command and Control (TA0011) | Exfiltration Over C2 Channel (T1041)<br>Scheduled Transfer (T1029)<br>Application Layer Protocol: Web Protocols (T1071.001) | yes | proxy |
| Deletion of the scheduled task | Defense Evasion (TA0005) | Indicator Removal: Clear Persistence (T1070.009) | yes | winevent |
| Deletion of a large number of `*.log.1` files on `\\SRV-STAGE-01\temp` | Defense Evasion (TA0005) | Indicator Removal: File Deletion (T1070.004) | yes | fileaudit |

---

## Repository Contents

| File / Folder | Description |
|---|---|
| `README.md` | This file |
| `northgate-investigation-report.pdf` | Full written investigation report |
| `northgate-data/` | Raw CSV log exports used during analysis, with the Splunk ingestion guide |
| `queries/` | SPL queries from the investigation by report section (question, query, finding), plus the timeline queries |
| `Final_Presentation.pdf` | Stakeholder-facing summary deck |
| `ai-verification-log-project.xlsx` | Record of where AI assistance was used, verified, corrected, or rejected during this investigation |

**Dataset:** the log data in `northgate-data/` was provided as part of a SOC Analyst course.
