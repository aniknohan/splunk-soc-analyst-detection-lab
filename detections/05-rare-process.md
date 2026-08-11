# Rare Process Hunting

## Objective

Find the least common process names as candidates for investigation.

## SPL

```spl
index=main
| rare process_name
```

Full search collection: [`../spl/06_rare_processes.spl`](../spl/06_rare_processes.spl)

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Rare does not mean malicious. Check host, user, execution time, path, command line, parent process, network connections, and endpoint-security detections.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
