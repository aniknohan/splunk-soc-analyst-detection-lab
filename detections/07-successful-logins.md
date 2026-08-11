# Successful Login Review

## Objective

Review successful authentication activity and identify logins that may require additional investigation, particularly successful logins occurring after repeated authentication failures.

## SPL

```spl
index=main sourcetype=secure "Accepted password"
| stats count by user src_ip
| sort - count
```

Full search collection: [`../spl/03_successful_logins.spl`](../spl/03_successful_logins.spl)

## Investigation Approach

### Investigation Objective

Identify successful authentications and determine whether the activity represents expected user behavior or requires additional investigation.

A successful login is normally legitimate. However, successful authentication becomes more security-relevant when it occurs after repeated failed attempts or involves an unexpected source IP, time, or user behavior.

### SPL Analysis

For Linux authentication logs, successful password authentication can be identified using:

```spl
index=main sourcetype=secure "Accepted password"
```

The `"Accepted password"` phrase identifies successful password authentications within the Linux authentication data used by this lab.

The results can then be summarized by user and source IP:

```spl
index=main sourcetype=secure "Accepted password"
| stats count by user src_ip
| sort - count
```

Grouping by `user` and `src_ip` helps determine which accounts successfully authenticated and which source addresses were responsible.

### Failed Login Followed by Success

One important authentication pattern to investigate is:

```text
Failure
   ↓
Failure
   ↓
Failure
   ↓
Success
```

A sequence of repeated authentication failures followed by a successful login can have both legitimate and suspicious explanations.

A legitimate user may simply enter an incorrect password several times before remembering the correct one.

However, the same pattern may also occur when password guessing or another credential attack eventually results in successful authentication.

For this reason, the successful login should be correlated with the authentication activity that occurred before it.

### Authentication Correlation

When a successful login follows suspicious failures, the analyst should determine:

- Which user successfully authenticated?
- Which source IP generated the successful login?
- Did the same source IP generate previous failures?
- Was the same account targeted during those failures?
- How many failures occurred before the successful authentication?
- How much time passed between the failures and success?
- Is the source IP expected for the user?
- Has the source IP been observed previously?
- Were other accounts targeted by the same source?

Reviewing these factors provides stronger investigative context than evaluating the successful login independently.

### Normal Successful Login Activity

Successful authentication can occur during normal activity such as:

- An employee beginning work.
- A remote employee authenticating through an approved VPN.
- An administrator performing authorized maintenance.
- A service account authenticating as part of an expected process.

These events should not automatically be treated as suspicious.

### Potentially Suspicious Login Context

A successful login may deserve additional investigation when associated with circumstances such as:

- Repeated failed logins immediately beforehand.
- An unfamiliar source IP address.
- Authentication outside the user's expected activity period.
- Unexpected authentication behavior for the account.
- Successful authentication following possible password guessing.

Location-based conclusions require appropriate identity, VPN, or geolocation telemetry and should not be inferred from the authentication event alone.

### Analyst Finding

A successful login by itself does not indicate malicious activity.

The event becomes more significant when surrounding authentication activity provides additional suspicious context, particularly when repeated failures involving the same user or source IP are followed by successful authentication.

Even in that situation, the sequence is an investigation signal rather than proof that an account has been compromised.

### Investigation Next Steps

- Identify the user associated with the successful authentication.
- Identify the source IP responsible for the login.
- Search for previous failed logins involving the same user.
- Search for previous failed logins involving the same source IP.
- Determine how many failures occurred before the successful login.
- Review the time between the failures and successful authentication.
- Determine whether the source IP is expected for the user.
- Determine whether the same source targeted additional accounts.
- Review activity performed by the account after authentication.
- Correlate the login with VPN, endpoint, firewall, EDR, or other authentication telemetry when available.
- Escalate unexplained successful authentication following suspicious failures when additional investigation is warranted.

## Why it matters

Successful authentication events can provide important evidence during account-compromise investigations. Correlating successful logins with previous failures can help analysts identify situations where repeated authentication attempts may have eventually succeeded.

## Analyst triage

Review the user, source IP, previous authentication failures, timing, historical behavior, and activity following the successful login before determining whether escalation is required.

## Production consideration

This is a lab investigation pattern. Authentication event formats, field names, correlation windows, expected login behavior, and available contextual data should be tuned to the organization's identity systems and data sources before operational use.
