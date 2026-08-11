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

### Targeted Account Analysis

After identifying a high-volume source, the analyst can determine which accounts are receiving the most failed authentication attempts:

```spl
index=main sourcetype=secure "Failed password"
| stats count by user
| sort -count
```

This helps identify heavily targeted accounts and determine whether privileged accounts such as `admin`, `root`, or `administrator` require additional attention.

### Analyst Finding

A source IP exceeding the failed-login threshold represents a higher-priority authentication anomaly that warrants investigation. Repeated failures may indicate password guessing, brute-force activity, misconfigured services, expired credentials, or legitimate users repeatedly entering incorrect passwords.

The threshold is an investigation trigger rather than proof of compromise. Its significance depends on the time window, targeted accounts, source reputation, historical behavior, and whether authentication eventually succeeded.

### Investigation Next Steps

### Investigation Next Steps

- Identify which user accounts were targeted by the source IP.
- Determine whether the activity targeted one account or multiple accounts.
- Prioritize review of privileged accounts such as `admin`, `root`, or `administrator`.
- Determine whether the source IP is internal or external.
- Review whether the source IP has been observed previously in the environment.
- Analyze the frequency and timing of the failed authentication attempts.
- Determine whether a successful authentication occurred after the repeated failures.
- If a success followed the failures, investigate the account for possible unauthorized access.
- Review subsequent activity associated with the authenticated user and source IP.
- Correlate the source with firewall, VPN, endpoint, EDR, and other authentication telemetry when available.
- Consider containment actions such as blocking the source only after validating the activity and following organizational policy.

### Detection Tuning

### Detection Tuning

The `count > 10` condition used in this lab is an investigation threshold, not proof of a brute-force attack.

In a production SOC, authentication thresholds should be tuned to the organization's normal behavior, time window, account type, authentication source, and expected failure rate. An analyst should consider the complete pattern rather than the failure count alone.

For example, repeated failures against privileged accounts, failures from an unusual external source, or a successful authentication immediately following numerous failures may increase the priority of the investigation.

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Determine whether the source is internal or external, whether it has been seen before, which accounts were targeted, whether privileged accounts were targeted, and whether any success followed the failures. Tune the threshold to the environment.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
