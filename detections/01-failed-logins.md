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

### Authentication Analysis

After identifying sources generating repeated failures, the investigation can be expanded to determine which users are affected and how the activity changes over time.

#### Failed Logins by User

```spl
index=main sourcetype=secure "Failed password"
| stats count by user
| sort -count
```

This identifies accounts experiencing the highest number of authentication failures. A high count may indicate a user repeatedly entering an incorrect password, a service-account configuration issue, or potentially suspicious authentication activity.

#### User and Source IP Correlation

```spl
index=main sourcetype=secure "Failed password"
| stats count by user src_ip
| sort -count
```

Grouping by both `user` and `src_ip` provides additional context by showing which source addresses are generating failures against specific accounts.

This can help distinguish activity concentrated against one account from activity affecting multiple users.

#### Top Failed-Login Sources

```spl
index=main sourcetype=secure "Failed password"
| top limit=5 src_ip
```

This quickly identifies the source IP addresses responsible for the largest share of failed authentication attempts and helps prioritize investigation.

#### Failed Logins Over Time

```spl
index=main sourcetype=secure "Failed password"
| timechart count
```

Reviewing authentication failures over time helps identify spikes or unusual periods of activity. A sudden increase may warrant further investigation, but the surrounding context should be reviewed before determining whether the activity is malicious.

The combination of user, source IP, failure volume, and timing provides stronger investigative context than any single failed-login event. Particular attention should be given to unusual sources, heavily targeted accounts, sudden increases in failures, and successful authentication occurring after repeated failures.

### Analyst Finding

Repeated failed authentication attempts from the same source can indicate password guessing, brute-force activity, credential attacks, or a legitimate authentication problem.

A high failure count alone does not confirm malicious activity. The source IP, targeted accounts, timing, historical behavior, and any subsequent successful authentication should be reviewed before determining severity.

### Investigation Next Steps

### Investigation Next Steps

- Identify which user accounts are experiencing the authentication failures.
- Identify the source IP addresses generating the failures.
- Determine whether the source IP is internal or external.
- Review whether the source IP has been observed previously.
- Determine whether one account or multiple accounts are being targeted.
- Review the volume and timing of the failed authentication attempts.
- Look for sudden increases or unusual patterns in failed-login activity.
- Determine whether a successful authentication occurred after repeated failures.
- If a success followed the failures, review subsequent account activity for signs of unauthorized access.
- Consider legitimate causes such as mistyped passwords, locked accounts, expired passwords, or outdated service-account credentials.
- Consider suspicious causes such as password spraying, brute-force activity, credential stuffing, or unauthorized access attempts.
- Correlate suspicious authentication activity with available endpoint, firewall, VPN, EDR, or other security telemetry.
  
## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Review the targeted user, source IP, number of failures, time pattern, and whether a success follows. Password mistakes, lockouts, expired passwords, and service-account issues can be legitimate causes.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
