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
