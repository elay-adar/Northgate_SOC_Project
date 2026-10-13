# 5b · Data & Impact

What was staged, collected, destroyed and taken, and what was ruled out.

Each entry shows the question, the SPL query, and the finding, as recorded in the investigation report (section 5). All searches run against `index=northgate`.

## 1. How did the attacker know how many POS machines there are?

```spl
index=northgate 77.124.66.19
```

**Finding:** We knew 77.124.66.19 is malicious so we filtered on that and saw the reconnaissance on all the POS’s

## 2. How many process creations did r.stern do?

```spl
index=northgate sourcetype=winevent EventCode=4688
|where actor="r.stern"
```

**Finding:** I found all the processes stern did and in there we saw the POS modifications and data gathering

## 3. Is y.oren a part of the attack?

```spl
index=northgate actor="y.oren" action="create"
```

**Finding:** We found that he created files which he is not supposed to, but after further investigation we found that he created files regarding his line of work

## 4. How many POS machines are available in the logs?

```spl
|inputlookup assets.csv
```

**Finding:** There we can see all the assets and we can see 38 different machines and 4 duplicates giving a total of 42

## 5. Has anyone else used the malicious exe files?

```spl
index=northgate ngpos-cfg.exe AND index=northgate ngpos-cfg.exe r.stern
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** I searched the whole log base for the exe file and found 34 events, and then i filtered by r.stern and saw 34 again, meaning no one else used those files

## 6. Had a.mizrahi used any abnormal exe files?

```spl
index=northgate sourcetype=winevent a.mizrahi EventCode=4688
|table _time, process
```

**Finding:** I found only legit processes such as outlook winword chrome excel etc

## 7. Which accounts move abnormal file volume?

```spl
index=northgate sourcetype=fileaudit
| stats count sum(bytes_out) by actor
```

**Finding:** FINDING — r.stern: 5,457 events, 466,845,388 bytes. 40× the ~110-event user baseline. Only svc_pricefeed is higher and is the sanctioned nightly price push.

## 8. Does any server show single-actor use?

```spl
index=northgate sourcetype=fileaudit
| stats count dc(actor) values(actor) by server
```

**Finding:** FINDING — SRV-STAGE-01: 5,360 events, exactly one actor across 90 days. SRV-FILE-HQ by contrast is used by 29 accounts.

## 9. Was that server in use before the incident?

```spl
index=northgate server=SRV-STAGE-01 latest="08/16/2026:00:00:00"
| stats count
```

**Finding:** NULL RESULT — zero events in the preceding 85 days. The first file activity on the host is the start of the harvest.

## 10. What was staged, how much, from where, and when?

```spl
index=northgate server=SRV-STAGE-01 action=write
| stats count sum(bytes_out) dc(src_host) min(_time) max(_time)
```

**Finding:** FINDING — 2,850 files, 450,879,900 bytes (430.0 MiB), 34 terminals, 2026-08-16 03:00:00 → 2026-08-19 22:34:19.

## 11. Was the collection manual or automated?

```spl
index=northgate server=SRV-STAGE-01 action=write
| bin _time span=1d
| stats count min(_time) max(_time) by _time
```

**Finding:** FINDING — 713/712/713/712 files per day, start and end identical to the second daily (03:00:00 → 22:34:19), ~101-second cadence, two parallel write streams. Automated.

## 12. Was evidence destroyed, and completely?

```spl
index=northgate action=delete
| stats count min(_time) max(_time); write-minus-delete comparison by object_path
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** PARTIAL — 2,510 files destroyed in 37m38s on 19/08. 340 files (53,820,040 bytes) were never deleted, spanning all 34 terminals.

## 13. Did collection stop during the cleanup?

```spl
index=northgate action=write earliest="08/19/2026:04:30:00" latest="08/19/2026:05:07:38"
```

**Finding:** NEGATIVE — no. 22 files were written during the deletion window; the two processes ran concurrently.

## 14. Did the activity stop at all?

```spl
index=northgate action=write earliest="08/19/2026:05:07:39"
```

**Finding:** NEGATIVE — no. 624 further files to 22:34:19. Data ends 20/08 11:56 with the operation still active.

## 15. What did the compromised account read?

```spl
index=northgate actor=r.stern action=read
| stats count sum(bytes_out) by server
```

**Finding:** NULL RESULT — zero reads on the staging server; all 5,360 events there are writes and deletes. The account's only reads are 80 Payments documents on \\SRV-FILE-HQ\Payments from its own workstation, spread across 90 days.

## 16. Did the source terminals have endpoint detection?

```spl
index=northgate action=write
| stats count by src_host
| lookup assets.csv hostname as src_host OUTPUT has_edr criticality
```

**Finding:** NULL RESULT — none. All 34 are has_edr=no, criticality=high, segment pos-branch. No process telemetry exists from any branch terminal.

## 17. Were all POS terminals affected?

```spl
index=northgate
| inputlookup assets.csv
| search hostname=POS-* compared against observed src_host
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** PARTIAL — 34 of 42. Four were enumerated then skipped despite logging normally; four emit no events at all. 34 is a floor, not a total.

## 18. Was the cloud platform the exfiltration channel?

```spl
index=northgate sourcetype=cloudaudit actor=r.stern
| stats count by operation; operation=share_link_create
| stats count by link_scope
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** NULL RESULT — no. 37 events spread evenly across 90 days with no clustering on 16–19/08. All 63 share links are internal scope; zero external.

## 19. Were backups deleted, failed or tampered with?

```spl
index=northgate sourcetype=backup
| stats count by status; weekly archive size trend
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** NULL RESULT — no. 103 of 103 jobs SUCCESS. Weekly card-processing archive ran all 13 weeks at 1,906–2,265 GB with no anomalous drop.

## 20. Is backup coverage adequate?

```spl
index=northgate sourcetype=backup
| stats count by target
```

**Finding:** GAP — all 103 jobs target SRV-FILE-HQ alone. All three critical servers are unprotected, as are SRV-STAGE-01 and all 42 terminals.

## 21. Was the cardholder environment accessed?

```spl
index=northgate sourcetype=winevent EventCode=5140 object_name="*CARDPROC*"
| stats count by actor src_host
```

**Finding:** NULL RESULT — no. All 74 connections to \\SRV-CARDPROC\Payments originate from four Payments workstations operated by their assigned users. None from SRV-VEND-APP or SRV-STAGE-01.

## 22. Were the POS price files tampered with?

```spl
index=northgate object_path="*\\prices\\*"
| stats count by actor action
```

**Finding:** NULL RESULT — no. All 27,360 events are svc_pricefeed writes, uniform at 40,000–46,300 bytes, continuing normally through 20/08.

## 23. Was anything taken from the file server?

```spl
index=northgate sourcetype=fileaudit src_host=SRV-VEND-APP
| stats count
```

**Finding:** NULL RESULT — no. During the four-night share enumeration, r.stern has zero file events on SRV-FILE-HQ and a.mizrahi has four, from their own workstation.

## 24. Was m.saban, the registered owner of the staging server, involved?

```spl
index=northgate actor=m.saban
| stats count by server; winevent
| stats count by src_host
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** RULED OUT — all 126 file events are on \\SRV-FILE-HQ\IT from WKS-IT-09; zero events on the server they own. All 522 winevent events originate from that same workstation.
