# 5c · Intel & Context

Outbound traffic, proxy and web server activity, and external context.

Each entry shows the question, the SPL query, and the finding, as recorded in the investigation report (section 5). All searches run against `index=northgate`.

## 1. Did the staged data leave the network?

```spl
index=northgate sourcetype=proxy src_host=SRV-STAGE-01 (cross-source, Intel & Context)
```

_The report lists this method in abbreviated form; adapt it before running._

**Finding:** FINDING — yes. Six POSTs to edge-sync-eu.net, 188,743,680 bytes (180.0 MiB), 19/08 02:55:01–04:10:01, all permitted. The only six proxy events that host generates in 90 days.

## 2. Was the account's earlier file activity malicious?

```spl
index=northgate actor=r.stern server=SRV-FILE-HQ
| stats count min(_time) max(_time) by action
```

**Finding:** COULD NOT DETERMINE — 97 events on \\SRV-FILE-HQ\Payments from the account's own workstation, matching its department and function, at 08:00–16:00 local. Not separable from legitimate work.

## 3. Who sends the most bytes out through the proxy?

```spl
index="northgate" sourcetype="proxy"
|table time, method, bytes_out, verdict, dest_host
|sort -bytes_out
```

**Finding:** SRV-STAGE-01 is take the six most bytes out requests to the proxy, all allowed

## 4. Did SRV-STAGE-01 speak to the proxy at other times as well?

```spl
index="northgate" sourcetype="proxy" src_host="SRV-STAGE-01" method != "POST"
```

**Finding:** No logs found

## 5. What other hosts talked with edge-sync-eu.net?

```spl
index="northgate" sourcetype="proxy" dest_host="edge-sync-eu.net"
| stats dc(src_host) values(src_host)
```

**Finding:** Only SRV-STAGE-01 sends packets to edge-sync-eu.ne.

## 6. What are the distinct user agents in the proxy? Are there any suspicious ones?

```spl
index=northgate sourcetype=proxy
| stats count by user_agent
| eval is_suspicious=case( isnull(user_agent) OR user_agent="" OR user_agent="-", "Suspicious: Missing User-Agent", len(user_agent) < 10, "Suspicious: Extremely short User-Agent", match(user_agent, "(?i)(curl|wget|python|powershell|cmd|nikto|sqlmap|nmap|go-http-client|java)"), "Suspicious: Automated/CLI tool", true(), "Legitimate / Standard" )
| stats count(user_agent) as total_distinct_user_agents, values(user_agent) as user_agent_list, values(is_suspicious) as analysis_status
```

**Finding:** There is no suspicious user agent

## 7. Are there users that their average volume of bytes out up to two weeks ago is at least half the average volume of bytes out over the last two weeks?

```spl
index="northgate" sourcetype="proxy" earliest="05/23/2026:11:08:27" latest="08/06/2026:23:59:59"
|bucket time span=1d
|stats sum(bytes_out) as bytes_per_day by src_host, time
|stats avg(bytes_per_day) as daily_avg_before_incident by src_host
|join type=left src_host [search index="northgate" sourcetype="proxy" earliest="08/07/2026:00:00:00" latest="08/20/2026:11:48:58" |bucket time span=1d |stats sum(bytes_out) as bytes_per_day by src_host, time |stats avg(bytes_per_day) as daily_avg_in_incident by src_host]
|where daily_avg_in_incident >= (daily_avg_before_incident*2)
```

**Finding:** WKS-HQ-13, WKS-HQ-20, WKS-IT-08 exhibited a significant anomaly by doubling their average daily outbound data traffic during the incident window compared to their baseline. After further investigation I concluded that this anomaly is not strong indicator for malicious activity.

## 8. What outbound proxy access was not approved for several unique machines?

```spl
index="northgate" sourcetype="proxy" verdict!="allowed"
| stats dc(src_host), values(src_host)
```

**Finding:** 30 machines found, no anomaly found

## 9. What IP addresses make the most requests to the WEB-SUPPLIER?

```spl
index="northgate" sourcetype=weblog
| stats count as total_requests, sum(bytes_out) as total_bytes_sent, dc(host) as unique_hosts_visited, dc(uri_path) as unique_paths_requested by src_ip
| eval total_MB = round(total_bytes_sent/1024/1024, 2)
| table src_ip, total_requests, total_MB, unique_hosts_visited, unique_paths_requested
| sort - total_requests
```

**Finding:** 77.124.66.31 made 91 requests and 77.124.66.19 made 48 requests while all the others made between 2-1 requests.

## 10. Which distinct paths those suspicious addresses accessed on the company's public website?

```spl
index=northgate sourcetype=weblog
|where src_ip="77.124.66.31" or src_ip="77.124.66.19"
| stats count(uri_path) as total_count, dc(uri_path) as unique_uri_count, values(uri_path) as requested_paths, sum(bytes_out) as total_bytes by src_ip
| table src_ip, total_count, unique_uri_count, requested_paths
```

**Finding:** 77.124.66.19 enumerate /supplier/api/v2/inventory branches - IDOR enumeration 77.124.66.31 access to 6 unique paths - no malicious activity was found.
