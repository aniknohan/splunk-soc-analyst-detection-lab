# Brute-Force Detection

## Objective

Surface source IPs whose failed-login volume exceeds the lab investigation threshold.

## SPL

```spl
index=main sourcetype=secure "Failed password"
| stats count by src_ip
| where count > 10
| sort - count
```

Full search collection: [`../spl/02_brute_force.spl`](../spl/02_brute_force.spl)

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Determine whether the source is internal or external, whether it has been seen before, which accounts were targeted, whether privileged accounts were targeted, and whether any success followed the failures. Tune the threshold to the environment.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
