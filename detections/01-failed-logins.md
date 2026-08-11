# Failed Login Analysis

## Objective

Identify users and source IPs generating repeated authentication failures.

## SPL

```spl
index=main sourcetype=secure "Failed password"
| stats count by src_ip
| sort - count
```

Full search collection: [`../spl/01_failed_logins.spl`](../spl/01_failed_logins.spl)

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Review the targeted user, source IP, number of failures, time pattern, and whether a success follows. Password mistakes, lockouts, expired passwords, and service-account issues can be legitimate causes.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
