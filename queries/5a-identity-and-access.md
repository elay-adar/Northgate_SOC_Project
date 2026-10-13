# 5a · Identity & Access

How the attacker got in and which accounts and processes were involved.

Each entry shows the question, the SPL query, and the finding, as recorded in the investigation report (section 5). All searches run against `index=northgate`.

## 1. Is e.katz’s 1116 Event ID malicious?

```spl
index=northgate sourcetype=winevent EventCode="1116"
```

**Finding:** We see the alert fired because of a windows defender trigger, and none malicious

## 2. How did the attacker get initial access?

```spl
index=northgate sourcetype=winevent
| where extracted_host="SRV-VEND-APP"
```

**Finding:** 3 logs containing the initial access and more

## 3. What are all the actions done with the malicious files (ngpos-cfg.exe,ngarch.exe) by r.stern, with the time difference between logs shown

```spl
index=northgate sourcetype=winevent EventCode=4688 actor="r.stern" process="ngpos-cfg.exe" OR process="ngarch.exe"
| streamstats window=1 current=f last(_time) as prev_time
| eval delta_seconds = prev_time - _time
| eval time_diff = tostring(abs(delta_seconds), "duration")
| table _time, extracted_host, process, cmdline,time_diff
| sort _time
```

**Finding:** Found that ngpos-cfg.exe ran on 34/42 POS’s terminals with defined intervals of 17 seconds, and after 2 days 22 hours ngarch.exe was used to collect all the data.

## 4. What are all the process creating event id 4698 that occurred

```spl
index=northgate sourcetype=winevent EventCode=4698
```

**Finding:** We only see the 2 we already knew about - creation of scheduled task and deletion after the POST requests through the proxy.

## 5. Did the attacker get access using kerberoasting?

```spl
index=northgate sourcetype=winevent EventCode=4769 OR EventCode=4768 earliest="08/01/2026:00:00:00" latest="08/20/2026:00:00:00"
| streamstats window=1 current=f last(_time) as prev_time
| eval delta_seconds = prev_time - _time
| eval time_diff = tostring(abs(delta_seconds), "duration")
|table _time, actor, EventCode, time_diff
```

**Finding:** After checking all the logs we didn't see any fixed intervals, I also checked a.mizrahi and r.stern alone. Nothing found, searched at different times as well.
