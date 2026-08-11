# Suspicious Process Execution

## Objective

Detect the lab example of Microsoft Word launching PowerShell.

## SPL

```spl
index=main parent_process="winword.exe" process_name="powershell.exe"
```

Full search collection: [`../spl/05_suspicious_process_execution.spl`](../spl/05_suspicious_process_execution.spl)

## Investigation Approach

### Investigation Objective

Identify unusual process execution patterns that may indicate malicious or attacker-related activity, with a focus on Microsoft Word launching PowerShell.

A suspicious process is not automatically malicious, but unusual process relationships should be investigated to determine whether the activity is expected.

### SPL Analysis

The detection searches for PowerShell execution where Microsoft Word is the parent process:

```spl
index=main
parent_process="winword.exe"
process_name="powershell.exe"
```

The `parent_process` field identifies the process that launched another process, while `process_name` identifies the process that was executed.

In this example, the relationship is:

```text
winword.exe -> powershell.exe
```

Microsoft Word normally handles document activity, so Word launching PowerShell represents an unusual process relationship that deserves investigation.

### Analyst Finding

The detection identifies a potentially suspicious parent-child process relationship between Microsoft Word and PowerShell.

This behavior may be security-relevant because attackers can abuse document execution to launch PowerShell or other command-line tools.

However, the process relationship alone does not confirm malicious activity. The event should be investigated in context before making a final determination.

### Investigation Next Steps

- Identify the user associated with the process activity.
- Identify the host where the processes executed.
- Review the PowerShell command that was executed.
- Determine whether the PowerShell execution was expected.
- Check whether PowerShell used encoded commands.
- Determine whether PowerShell attempted to download files from the Internet.
- Review whether additional suspicious processes executed afterward.
- Investigate unexpected executables running from temporary locations.

### Example Suspicious Execution Chain

A potential attack sequence may appear as:

```text
Email Attachment
      ↓
Microsoft Word
      ↓
PowerShell
      ↓
Downloads Malware
      ↓
Runs Malware
      ↓
Steals Credentials
```

Monitoring process creation and parent-child process relationships can help SOC analysts identify suspicious execution early in an investigation.

### Additional Suspicious Process Indicators

Other process behaviors that may deserve investigation include:

- Microsoft Word launching PowerShell.
- Command Prompt launching from Word or Excel.
- PowerShell executing encoded commands.
- PowerShell downloading files from the Internet.
- Programs running unexpectedly from the Temp folder.
- Unknown executable files starting automatically.

These behaviors are indicators for investigation and should not automatically be classified as malicious.

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Review parent/child process context, command line, user, host, execution path, and activity immediately before and after the process launch.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
