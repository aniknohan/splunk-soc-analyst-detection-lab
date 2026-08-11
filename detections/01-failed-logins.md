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

## Investigation Approach

### Investigation Objective

Identify accounts and source IP addresses generating repeated authentication failures and determine whether the activity represents normal user behavior or potentially malicious authentication attempts.

### SPL Analysis

The search filters Linux authentication events for `"Failed password"`, groups the results by `src_ip`, counts the number of failures associated with each source, and sorts the results from highest to lowest.

This allows the analyst to quickly prioritize the sources responsible for the largest number of authentication failures.

### Analyst Finding

Repeated failed authentication attempts from the same source can indicate password guessing, brute-force activity, credential attacks, or a legitimate authentication problem.

A high failure count alone does not confirm malicious activity. The source IP, targeted accounts, timing, historical behavior, and any subsequent successful authentication should be reviewed before determining severity.

### Investigation Next Steps

- Identify which user accounts were targeted.
- Determine whether the source IP is internal or external.
- Review the timing and frequency of the authentication failures.
- Check whether the source IP has appeared previously in the environment.
- Determine whether a successful login occurred after the failures.
- Check whether multiple accounts were targeted by the same source.
- Correlate the activity with endpoint, firewall, EDR, or other authentication telemetry when available.

  
## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Review the targeted user, source IP, number of failures, time pattern, and whether a success follows. Password mistakes, lockouts, expired passwords, and service-account issues can be legitimate causes.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
