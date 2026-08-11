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

## Investigation Approach

### Investigation Objective

Identify source IP addresses generating failed authentication attempts above the defined investigation threshold and determine whether the activity is consistent with brute-force behavior.

### SPL Analysis

The search filters authentication events containing `"Failed password"`, aggregates the failures by `src_ip`, and applies `where count > 10` to isolate sources exceeding the lab threshold.

Sorting the results by count allows the analyst to prioritize the highest-volume sources for investigation rather than reviewing every authentication failure individually.

### Analyst Finding

A source IP exceeding the failed-login threshold represents a higher-priority authentication anomaly that warrants investigation. Repeated failures may indicate password guessing, brute-force activity, misconfigured services, expired credentials, or legitimate users repeatedly entering incorrect passwords.

The threshold is an investigation trigger rather than proof of compromise. Its significance depends on the time window, targeted accounts, source reputation, historical behavior, and whether authentication eventually succeeded.

### Investigation Next Steps

- Identify the accounts targeted by the source IP.
- Determine whether one account or multiple accounts were targeted.
- Check whether privileged or administrative accounts were involved.
- Review the time pattern to determine how quickly the failures occurred.
- Determine whether the source IP is internal or external.
- Review previous activity associated with the source IP.
- Check whether a successful authentication followed the failed attempts.
- Correlate the source with firewall, endpoint, EDR, VPN, or other authentication telemetry when available.
- Escalate for additional investigation if the activity is unexplained or shows signs of successful account access.

### Detection Tuning

The `count > 10` condition is a lab investigation threshold and should not be treated as a universal production value. In a real SOC environment, the threshold and time window should be baselined and tuned to normal authentication behavior to reduce false positives while maintaining useful detection coverage.

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Determine whether the source is internal or external, whether it has been seen before, which accounts were targeted, whether privileged accounts were targeted, and whether any success followed the failures. Tune the threshold to the environment.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
