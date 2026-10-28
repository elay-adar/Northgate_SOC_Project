# Timeline queries

The queries cited by number in the report's incident timeline and evidence excerpts (Appendix B). All run against `index=northgate`.

## Query 1

```spl
index=northgate sourcetype=weblog src_ip="77.124.66.19"
| table time, src_ip, uri_path, status, bytes_out, method, user_agent
| sort time
```

## Query 2

```spl
index=northgate sourcetype=winevent
| where extracted_host="SRV-VEND-APP"
| table _time, extracted_host, EventCode, actor, src_host, logon_type, cmdline, target_account, object_name
|sort _time
```

## Query 3

```spl
index=northgate sourcetype=winevent src_host="SRV-VEND-APP" extracted_host="SRV-FILE-HQ"
| where EventCode=4672 or EventCode=4624
| sort _time
```

## Query 4

```spl
index=northgate sourcetype=winevent EventCode=5140 src_host="SRV-VEND-APP" extracted_host="SRV-FILE-HQ" actor="a.mizrahi"
| stats count min(_time) as min_time_epoch by object_name
| sort min_time_epoch
| streamstats current=f window=1 last(min_time_epoch) as prev_time_epoch
| eval time_diff_sec = min_time_epoch - prev_time_epoch
| eval time_diff = tostring(time_diff_sec, "duration")
| eval min_time = strftime(min_time_epoch, "%Y-%m-%d %H:%M:%S")
| table object_name count min_time time_diff
```

## Query 5

```spl
index=northgate sourcetype=winevent EventCode=4624 src_host="SRV-VEND-APP" extracted_host="SRV-POSMGT" actor="r.stern"
| lookup assets hostname AS src_host OUTPUT owner AS current_src_owner
| lookup assets owner AS actor OUTPUT hostname AS typical_user_hostname
| eval is_expected_hostname = if(lower(typical_user_hostname) == lower(src_host), "True", "False")
| table _time, actor, typical_user_hostname, src_host, current_src_owner, is_expected_hostname, extracted_host
```

## Query 6

```spl
index=northgate sourcetype=fileaudit server="SRV-STAGE-01" object_path="*.log.1*" latest="08/19/2026:00:10:01"
| stats dc(object_path) as object_path_count sum(bytes_out) as total_bytes_out
| eval total_MB_transfered = round(total_bytes_out / 1024 / 1024, 2)
| fields object_path_count, total_MB_transfered
```

## Query 7

```spl
index=northgate sourcetype=winevent EventCode=4688 actor="r.stern" (process="ngpos-cfg.exe" OR process="ngarch.exe")
| sort _time
| streamstats window=1 current=f last(_time) as prev_time
| eval delta_seconds = _time - prev_time
| eval time_diff = tostring(abs(delta_seconds), "duration")
| eval _time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table _time, extracted_host, process, cmdline, time_diff
```

## Query 8

```spl
index=northgate sourcetype=fileaudit actor="r.stern" src_host!="WKS-PAY-02" src_host!="SRV-STAGE-01"
| rex field=object_path "(?<file_type>\.[^\\\\]+)$"
| fillnull value="no_extension" file_type
| stats dc(object_path) as distinct_files values(action) as actions values(file_type) as file_types sum(bytes_out) as bytes min(_time) as first_seen max(_time) as last_seen by src_host, server
| eventstats sum(bytes) as total_bytes values(file_types) as all_file_types dc(src_host) as total_hosts
| eval MB_per_host=round(bytes/1024/1024,2), total_MB=round(total_bytes/1024/1024,2)
| eval only_log1=if(mvcount(all_file_types)=1 AND mvindex(all_file_types,0)=".log.1","yes","no")
| sort first_seen
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table src_host, server, distinct_files, actions, MB_per_host, first_seen, last_seen, total_hosts, total_MB, only_log1, all_file_types
```

## Query 9

```spl
index=northgate sourcetype=proxy src_host="SRV-STAGE-01"
| eval MB_out = round(sum(bytes_out/1024/1024),2)
| table time, method, MB_out, verdict, dest_host
| eventstats sum(MB_out) as total_MB_out
| sort time
```

## Query 10

```spl
index=northgate sourcetype=fileaudit src_host="SRV-STAGE-01" actor="r.stern" action="delete"
| stats count as deleted_files, min(_time) as min_time, max(_time) as max_time
| eval duration_sec = max_time - min_time
| eval duration = tostring(duration_sec, "duration")
| eval first_delete = strftime(min_time, "%Y-%m-%d %H:%M:%S"), last_delete = strftime(max_time, "%Y-%m-%d %H:%M:%S")
| table deleted_files first_delete last_delete duration
```

## Query 11

```spl
index=northgate sourcetype=fileaudit actor="r.stern" earliest="08/19/2026:04:30:00" latest="08/19/2026:05:07:38"
| where src_host!="WKS-PAY-02" and src_host!="SRV-STAGE-01"
| stats count, dc(object_path) as distinct_object_path, values(action) as action, sum(bytes_out) as total_bytes, min(time) as min_time, max(time) as max_time by src_host, server
| eventstats sum(count) as total_actions_all, sum(total_bytes) as total_bytes_all
| eval MB_transferred = round(total_bytes / 1024 / 1024, 2)
| eval total_MB_transferred_all = round(total_bytes_all / 1024 / 1024, 2)
| sort min_time
| where distinct_object_path=count
| table src_host, server, count, distinct_object_path, action, MB_transferred, min_time, max_time, total_actions_all, total_MB_transferred_all
```

## Query 12

```spl
index=northgate sourcetype=winevent EventCode=5140 actor="a.mizrahi" src_host="SRV-VEND-APP" extracted_host="SRV-FILE-HQ"
| eventstats count as total_count_share_folders
| stats dc(object_name) as distinct_share_folders values(object_name) as values_share_folders min(_time) as first_seen max(_time) as last_seen
| eval first_time_formatted=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_time_formatted=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| fields - first_seen, last_seen
```

## Query 13

```spl
index=northgate sourcetype=fileaudit src_host=SRV-VEND-APP
| stats count
```

## Query 14

```spl
index=northgate sourcetype=fileaudit actor="r.stern"
| where src_host!="WKS-PAY-02" and src_host!="SRV-STAGE-01"
| stats min(_time) as min_time, max(_time) as max_time by src_host, server
| sort limit=1 -max_time
| eval min_time=strftime(min_time, "%Y-%m-%d %H:%M:%S")
| eval max_time=strftime(max_time, "%Y-%m-%d %H:%M:%S")
```
