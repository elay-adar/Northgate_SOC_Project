# Northgate Retail - Supplier Portal to POS Data Exfiltration Investigation

**Investigation Team:** Elay Adar (Case Lead), Yossef (Identity & Access), Gavriel (Data & Impact)

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

## 3. Attack Timeline

Chronology of the incident as reconstructed in the investigation report (section 4). Times are UTC; rows marked "Translated UTC+3" are Windows event log (winevent) entries converted from UTC+3, as in the report. Each entry links to the query behind it.

| Time (UTC) | Source | Host / Actor | What happened | Query |
|---|---|---|---|---|
| 2026-08-09 07:12:00 | weblog | `WEB-SUPPLIER` / `77.124.66.19` | Successful `POST /supplier/login`. The account cannot be identified: weblog has no user field. | [#1](queries/timeline.md#query-1) |
| 2026-08-09 07:40:01 → 07:47:54 | weblog | `WEB-SUPPLIER` / `77.124.66.19` | 44 API requests enumerating branches B01–B38 at fixed 11.0 s intervals, all HTTP 200 (`/supplier/api/v2/inventory?branch=B<number>`). | [#1](queries/timeline.md#query-1) |
| 2026-08-10 23:04:01 <br>(Translated UTC+3) | winevent 4688 | `SRV-VEND-APP` / `IIS APPPOOL\supplier` | `w3wp.exe` spawns `cmd.exe` running `whoami`, `ipconfig /all` and `net view`. | [#2](queries/timeline.md#query-2) |
| 2026-08-10 23:31:01 <br>(Translated UTC+3) | winevent 4698 | `SRV-VEND-APP` / `IIS APPPOOL\supplier` | Scheduled task `NGSupplierSync` configured to run every 4 hours without specifying a program. Command: `schtasks /create /tn NGSupplierSync /sc hourly /mo 4`. | [#2](queries/timeline.md#query-2) |
| 2026-08-11 02:15:01 <br>(Translated UTC+3) | winevent 4624 + 4672 | `SRV-FILE-HQ` / `a.mizrahi` from `SRV-VEND-APP` | `a.mizrahi` logon (type 3) to `SRV-FILE-HQ` from `SRV-VEND-APP`, with special privileges (4672). | [#3](queries/timeline.md#query-3) |
| 2026-08-12 22:00:00 → 2026-08-15 22:46:12 <br>(Translated UTC+3) | winevent 5140 | `SRV-FILE-HQ` / `a.mizrahi` from `SRV-VEND-APP` | 40 events across 6 distinct shared folder paths. No files touched. | [#12](queries/timeline.md#query-12), [#13](queries/timeline.md#query-13) |
| 2026-08-15 21:46:59 <br>(Translated UTC+3) | winevent 4624 | `SRV-POSMGT` / `r.stern` from `SRV-VEND-APP` | `r.stern` logon (type 3) to `SRV-POSMGT` from `SRV-VEND-APP`, the first of its kind in 90 days. Baseline: logons from `SRV-POSMGT`, `SRV-CARDPROC` and `WKS-PAY-02`. | [#5](queries/timeline.md#query-5) |
| 2026-08-16 01:19:59 → 01:29:20 <br>(Translated UTC+3) | winevent 4688 | 34 × POS / `r.stern` | Automated distribution of a configuration file across 34 POS machines at fixed 17-second intervals. Command: `ngpos-cfg.exe /apply /src \\SRV-POSMGT\cfg\pos-profile.dat`. | [#7](queries/timeline.md#query-7) |
| 2026-08-16 03:00:00 | fileaudit | `SRV-STAGE-01` / `r.stern` | Collection begins on `\\SRV-STAGE-01\temp`. | [#8](queries/timeline.md#query-8) |
| 2026-08-16 → 2026-08-19, daily 03:00:00–22:34:19 | fileaudit | `SRV-STAGE-01` / `r.stern` from `POS-B<number>-01` × 34 | Every POS machine writes between 83 and 84 distinct `*.log.1` files (712.5 files per day, 430 MB in total). | [#8](queries/timeline.md#query-8) |
| 2026-08-18 00:10:01 <br>(Translated UTC+3) | winevent 4688 | `SRV-STAGE-01` / `r.stern` | Archive created from 1,425 files (214.93 MB). Command: `ngarch.exe -a -q -o D:\temp\ngsync-0819.dat \\SRV-STAGE-01\temp\*.log.1`. | [#7](queries/timeline.md#query-7), [#6](queries/timeline.md#query-6) |
| 2026-08-19 02:55:01 → 04:10:01 | proxy | `SRV-STAGE-01` / unknown | 6 POSTs to `edge-sync-eu.net`, 180 MB in total, 15 minutes apart, all allowed. | [#9](queries/timeline.md#query-9) |
| 2026-08-19 04:30:00 <br>(Translated UTC+3) | winevent 4698 | `SRV-VEND-APP` / `IIS APPPOOL\supplier` | Scheduled task `NGSupplierSync` deleted. Command: `schtasks /delete /tn NGSupplierSync /f`. | [#2](queries/timeline.md#query-2) |
| 2026-08-19 04:30:00 → 05:07:38 | fileaudit | `SRV-STAGE-01` / `r.stern` | 2,510 files destroyed in 37m 38s. 22 files were written during the window: collection never paused. | [#10](queries/timeline.md#query-10), [#11](queries/timeline.md#query-11) |
| 2026-08-19 22:34:19 | fileaudit | `SRV-STAGE-01` / `r.stern` | Last staged write. 340 files never deleted (53,820,040 bytes), spanning all 34 terminals. | [#14](queries/timeline.md#query-14) |

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

Technique-level mapping of the attack chain, with the detection status recorded in the investigation report (section 8). The `a.mizrahi` account takeover is the one stage marked as not detected; no detection is recorded for the `r.stern` takeover.

| Stage | Tactic | Technique | Detected | Source |
|---|---|---|---|---|
| `POST /supplier/login` | Initial Access (TA0001) | Valid Accounts (T1078) | yes | weblog |
| 44 API requests enumerating `/inventory` | Reconnaissance (TA0043) | Active Scanning (T1595)<br>Active Scanning: Wordlist Scanning (T1595.003) | yes | weblog |
| `w3wp.exe` spawns `cmd.exe` and runs `whoami`, `ipconfig /all`, `net view` | Execution (TA0002), Discovery (TA0007) | Command and Scripting Interpreter: Windows Command Shell (T1059.003)<br>System Owner/User Discovery (T1033)<br>System Network Configuration Discovery (T1016)<br>Network Share Discovery (T1135)<br>Network Service Discovery (T1046) | yes | winevent |
| Scheduled task creation | Persistence (TA0003), Privilege Escalation (TA0004) | Scheduled Task/Job: Scheduled Task (T1053.005) | yes | winevent |
| Account takeover of `a.mizrahi` on SRV-VEND-APP, admin credentials used from the compromised host | Privilege Escalation (TA0004), Lateral Movement (TA0008), Credential Access (TA0006) | Valid Accounts: Domain Accounts (T1078.002)<br>Use Alternate Authentication Material (T1550)<br>OS Credential Dumping (T1003) | no | winevent |
| `a.mizrahi` logon type 3 from SRV-VEND-APP | Lateral Movement (TA0008), Defense Evasion (TA0005) | Remote Services (T1021)<br>Valid Accounts: Domain Accounts (T1078.002) | yes | winevent |
| Automated network share enumeration (SMB event 5140) | Discovery (TA0007), Collection (TA0009) | Network Share Discovery (T1135)<br>Data from Network Shared Drive (T1039) | yes | fileaudit |
| Account takeover of `r.stern` on SRV-VEND-APP | Privilege Escalation (TA0004), Lateral Movement (TA0008), Credential Access (TA0006) | Valid Accounts: Domain Accounts (T1078.002)<br>Use Alternate Authentication Material (T1550)<br>OS Credential Dumping (T1003) | - | - |
| `r.stern` logon type 3 from SRV-VEND-APP | Lateral Movement (TA0008) | Remote Services: SMB/Windows Admin Shares (T1021.002)<br>Valid Accounts: Domain Accounts (T1078.002) | yes | winevent |
| Automated POS profile deployment via `ngpos-cfg.exe` | Execution (TA0002), Defense Evasion (TA0005) | System Services: Service Execution (T1569.002)<br>Abuse Elevation Control Mechanism (T1548) | yes | winevent |
| Data collection on `\\SRV-STAGE-01\temp` in `.log.1` format | Collection (TA0009) | Archive Collected Data (T1560)<br>Data Staged: Local Data Staging (T1074.001) | yes | fileaudit |
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
