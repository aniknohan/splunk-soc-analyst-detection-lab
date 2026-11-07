# BOTS-001 SPL search pack

Run with **No Event Sampling**. Use the sourcetype inventory in the [setup guide](README.md) before running the queries. Replace field names only after checking the raw data and extracted fields. For correlation, set both searches to the same narrow time window after identifying the firewall event, and record the display time zone.

## 1. Rank firewall IPS signatures

```spl
index=botsv1 earliest=0 sourcetype=fortigate_utm attack=*
| stats count dc(srcip) as unique_sources dc(dstip) as unique_targets by attack
| sort - count
```

Pick a category and open its underlying events. Compare volume with distinct sources and targets. High volume can indicate repeated scanning or duplicated activity.

## 2. Find reverse-shell alert candidates

```spl
index=botsv1 earliest=0 sourcetype=fortigate_utm "MS.Windows.CMD.Reverse.Shell"
| table _time srcip srcport dstip dstport attack severity action ref
| sort 0 _time
```

The supplied exercise identifies `192.168.250.70` and `23.22.63.114` as pivots. Verify direction from the raw firewall event. Record the reported action and signature. Use the actual event timestamp to narrow the next searches.

## 3. Corroborate with Suricata

```spl
index=botsv1 sourcetype=suricata "192.168.250.70" "23.22.63.114"
| spath
| table _time src_ip src_port dest_ip dest_port event_type alert.signature flow_id
| sort 0 _time
```

Inspect addresses, ports and direction in the raw JSON. Text matches are candidates. Shared addresses alone do not establish the same connection. Compare timestamp and available connection attributes. An empty result may reflect sensor placement, log coverage, or parsing.

## 4. Identify the endpoint

```spl
index=botsv1 sourcetype=xmlwineventlog "192.168.250.70" "23.22.63.114"
| eval event_code=coalesce(EventCode, EventID), endpoint=coalesce(Computer, ComputerName, host)
| table _time endpoint event_code SourceIp SourceHostname DestinationIp DestinationHostname Image ProcessGuid
| sort 0 _time
```

Inspect the raw XML and confirm which hostname belongs to the internal IP. If a matching Sysmon network event exposes a process GUID, pivot on that GUID and the endpoint to find its process creation event. Record command line, parent and account if available. A process image or a signature alone does not prove a shell.

## 5. Review scanner context separately

```spl
index=botsv1 earliest=0 sourcetype=suricata "Acunetix"
| spath
| table _time src_ip dest_ip alert.signature http.http_user_agent
| sort 0 _time
```

Record a scanner version only if the event includes version evidence. A user-agent string can be spoofed. Compare against the firewall scanner signature as a separate triage path.

## 6. Compare severity distributions within each product

```spl
index=botsv1 earliest=0 sourcetype=suricata
| spath
| search event_type=alert
| eval vendor_severity=coalesce(severity, 'alert.severity', "unknown")
| stats count by vendor_severity
| eventstats sum(count) as total
| eval percent=round(100*count/total,2)
| sort - count
```

```spl
index=botsv1 earliest=0 sourcetype=fortigate_utm attack=*
| eval vendor_severity=coalesce(severity,"unknown")
| stats count by vendor_severity
| eventstats sum(count) as total
| eval percent=round(100*count/total,2)
| sort - count
```

Keep denominators separate. Vendor severity labels can represent different scales. Report the dataset edition, time range, filters, counts and percentages together.
