# Northgate Retail Ltd — Investigation Dataset Setup & Ingestion Guide

## Executive Summary
This document serves as the official operational guide for ingesting, indexing, and validating the **Northgate Retail Ltd** investigation dataset within Splunk. The dataset contains **58,194 total events** across 7 primary log sources and 2 critical lookup tables, establishing the foundational environment for threat hunting and incident response scenarios.

---

## Dataset Metadata

| File Name | Sourcetype | Timezone | Record Count | File Type |
| :--- | :--- | :--- | :--- | :--- |
| `northgate_winevent.csv` | `winevent` | UTC+3 | 11,526 | Event Log |
| `northgate_fileaudit.csv` | `fileaudit` | UTC | 35,528 | Audit Log |
| `northgate_vpn.csv` | `vpn` | UTC | 540 | Telemetry |
| `northgate_proxy.csv` | `proxy` | UTC | 4,838 | Web Proxy |
| `northgate_weblog.csv` | `weblog` | UTC | 4,970 | Web Server |
| `northgate_cloudaudit.csv` | `cloudaudit` | UTC | 689 | Cloud Audit |
| `northgate_backup.csv` | `backup` | UTC | 103 | Infrastructure |
| `identity.csv` | N/A | N/A | 34 | Lookup Table |
| `assets.csv` | N/A | N/A | 79 | Lookup Table |

> **Critical Timezone Note:** `winevent` is recorded in **UTC+3**. All other log sources are recorded in **UTC**. There is no timezone offset column within the raw files; ensure time calculations account for this difference during investigation.

---

## Splunk Ingestion & Configuration Workflow

### Step 1: Log Files Ingestion
For each of the seven CSV log files, execute the following configuration steps:

1. Navigate to **Settings** > **Add Data** > **Upload**.
2. Select and upload the target file.
3. **Set Source Type:** If columns do not automatically populate in the preview pane, manually select `Structured` > `csv`.
4. **Save As:** Assign the exact `sourcetype` name specified in the metadata table above.
5. **Index Assignment:** Assign all files to the target index: `northgate` *(Create the index prior to upload if it does not exist)*.

### Step 2: Lookups Setup
Lookup tables require manual registration to enable enrichment commands:

1. **Upload Tables:** Navigate to **Settings** > **Lookups** > **Lookup table files** and upload both `identity.csv` and `assets.csv`.
2. **Define Lookups:** Navigate to **Settings** > **Lookups** > **Lookup definitions** and create a corresponding definition for each file.

> **Operational Warning:** Failure to define lookup definitions will cause the Splunk `lookup` command to fail during query execution.

### Step 3: Time Picker Configuration
Set the Splunk search time picker to **All time**. The dataset timeline spans from `2026-05-23 01:02:22` to `2026-08-20 11:58:44`. Default Splunk search windows will return zero results.

---

## Pre-Investigation Sanity Checks

Execute the following Splunk Processing Language (SPL) queries to verify data integrity and parsing accuracy before commencing analysis.

### 1. Sourcetype Event Count Verification
```spl
index=northgate | stats count by sourcetype
```
Expected result: seven rows that match the record counts in the metadata table (58,194 events in total).

| sourcetype | count |
| :--- | ---: |
| `fileaudit` | 35,528 |
| `winevent` | 11,526 |
| `proxy` | 4,838 |
| `weblog` | 4,970 |
| `cloudaudit` | 689 |
| `vpn` | 540 |
| `backup` | 103 |

### 2. Time Range Verification
```spl
index=northgate
| stats min(_time) as first_event max(_time) as last_event by sourcetype
| convert ctime(first_event) ctime(last_event)
```
Expected result: all sources fall between `2026-05-23 01:02:22` and `2026-08-20 14:58:44`, as stored in the files. The latest `winevent` value (`2026-08-20 14:58:44`) is `11:58:44` in UTC, which is the end of the dataset stated above. No source should show a date outside this range.

### 3. Windows Event Field Parsing
```spl
index=northgate sourcetype=winevent
| stats count by EventCode
```
Expected result: nine event codes. If `EventCode` is empty, the CSV was not parsed as `Structured`: repeat Step 1 for this file.

| EventCode | count |
| :--- | ---: |
| `4624` | 5,405 |
| `5140` | 1,225 |
| `4769` | 2,497 |
| `4634` | 1,796 |
| `4688` | 483 |
| `4672` | 61 |
| `4625` | 56 |
| `4698` | 2 |
| `1116` | 1 |

### 4. File Audit Action Check
```spl
index=northgate sourcetype=fileaudit
| stats count by action
```
Expected result:

| action | count |
| :--- | ---: |
| `write` | 30,408 |
| `read` | 2,385 |
| `delete` | 2,510 |
| `create` | 225 |

### 5. Lookup Verification
```spl
| inputlookup assets.csv | stats count
```
```spl
| inputlookup identity.csv | stats count
```
Expected result: `79` rows for `assets.csv` and `34` rows for `identity.csv`. If the search returns an error, the lookup table file or its definition from Step 2 is missing.

Once all five checks match, the dataset is ready for investigation.
