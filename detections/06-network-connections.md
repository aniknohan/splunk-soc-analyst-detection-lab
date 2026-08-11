# Network Connection Anomalies

## Objective

Identify sources touching many destination ports or generating unusually high connection volume.

## SPL

```spl
index=main
| stats dc(dest_port) as Ports by src_ip
| where Ports > 20
```

Full search collection: [`../spl/07_network_connections.spl`](../spl/07_network_connections.spl)

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Confirm whether the source is a workstation, server, scanner, management host, or other expected high-volume system. Review destination IPs, ports, protocol, and time window before escalating.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
