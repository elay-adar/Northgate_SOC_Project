Northgate Retail Ltd — Investigation Dataset
Read this file before uploading anything to Splunk.

Dataset Contents

Seven log sources and two lookup files. All are CSV files with a header row.

File                        sourcetype   Timezone   Rows
northgate_winevent.csv      winevent     UTC+3      11,526
northgate_fileaudit.csv     fileaudit    UTC        35,528
northgate_vpn.csv           vpn          UTC        540
northgate_proxy.csv         proxy        UTC        4,838
northgate_weblog.csv        weblog       UTC        4,970
northgate_cloudaudit.csv    cloudaudit   UTC        689
northgate_backup.csv        backup       UTC        103
identity.csv                lookup       —          34
assets.csv                  lookup       —          79

Total: 58,194 events.

Timezones

winevent is recorded in UTC+3.
All other sources are recorded in UTC.
There is no timezone offset column in any file, and it will not be explicitly flagged for you.

Splunk Ingestion

For each of the seven log files:

Settings > Add Data > Upload

Select the file

Set Source Type — if columns do not populate in the preview pane,
select Structured > csv

Save As — assign the exact sourcetype name from the table above

Index: northgate (create this index if it does not already exist)

The two lookup files must be uploaded separately:

Settings > Lookups > Lookup table files — Upload identity.csv and assets.csv
Settings > Lookups > Lookup definitions — Define a lookup definition for each file

Without the lookup definitions, the lookup command will fail to locate them.

Time Picker

Set the time picker to "All time".
The dataset spans from 2026-05-23 01:02:22 to 2026-08-20 11:58:44.
Splunk's default time range will return zero results.

Sanity Checks — Run these queries before starting your investigation

index=northgate | stats count by sourcetype

Expected output:
winevent    11,526
fileaudit   35,528
vpn         540
proxy       4,838
weblog      4,970
cloudaudit  689
backup      103

index=northgate | stats count

Expected output: 58,194

index=northgate sourcetype=fileaudit | head 3 | table _time actor object_path

Expected output: Three rows with three distinct columns.
If a single raw text string is returned, the file was not parsed as CSV.
Return to Section 3, Step 3, and select Structured > csv.

| inputlookup identity.csv | stats count

Expected output: 34

| inputlookup assets.csv | stats count

Expected output: 79

index=northgate | stats min(_time) as first max(_time) as last

Note: The maximum timestamp will originate from winevent and will appear later due to its offset.
This is intentional. Refer back to Section 2.
