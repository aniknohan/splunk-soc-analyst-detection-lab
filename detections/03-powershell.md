# Suspicious PowerShell Activity

## Objective

Find PowerShell executions with common suspicious command-line patterns such as encoding, hidden windows, execution-policy bypass, or download behavior.

## SPL

```spl
index=main process_name="powershell.exe"
| search Invoke-WebRequest OR DownloadFile OR Net.WebClient
```

Full search collection: [`../spl/04_powershell_detection.spl`](../spl/04_powershell_detection.spl)

## Investigation Approach

### Investigation Objective

Identify potentially suspicious PowerShell execution by examining command-line arguments and execution context for behaviors commonly associated with attacker activity.

### Detection Indicators

The investigation focuses on PowerShell activity containing indicators such as:

- `-EncodedCommand` or `-enc`
- `-ExecutionPolicy Bypass`
- `-WindowStyle Hidden` or `-w hidden`
- `Invoke-WebRequest`
- `DownloadFile`
- `Net.WebClient`
- `IEX` / `Invoke-Expression`

These indicators can be associated with command obfuscation, hidden execution, policy bypass, or file-download activity. However, their presence alone does not prove malicious execution.

### SPL Analysis

PowerShell activity can first be isolated by process name and important investigation fields:

```spl
index=main process_name="powershell.exe"
| table _time host user process_name command_line

Encoded PowerShell execution can then be investigated with:

```spl
index=main process_name="powershell.exe"
("EncodedCommand" OR "-enc")
```

Potential download behavior can be identified with:

```spl
index=main process_name="powershell.exe"
| search Invoke-WebRequest OR DownloadFile OR Net.WebClient
```

### Analyst Finding

PowerShell is a legitimate Windows administration tool, so PowerShell execution should not automatically be classified as malicious.

Suspicion increases when PowerShell is executed with encoded commands, hidden-window options, execution-policy bypasses, download functionality, or other unusual command-line arguments—especially when the activity is unexpected for the user or host.

### Investigation Next Steps

- Identify the user who executed PowerShell.
- Identify the host where the process executed.
- Review the complete PowerShell command line.
- Determine whether the activity was expected for the user or system.
- Decode encoded PowerShell content when appropriate.
- Determine whether PowerShell attempted to download a file.
- Review the parent process that launched PowerShell.
- Check for subsequent child processes or executable files.
- Correlate the activity with Windows Event Logs, Sysmon, Microsoft Defender, or EDR telemetry when available.
- Escalate unexplained activity involving suspicious command-line indicators for additional investigation.

### Example Investigation Scenario

Consider the following execution:

```text
powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBt...
```

An analyst should not immediately classify this as malicious. The investigation should determine who executed the command, which system executed it, whether the activity was expected, what the encoded content contains, and whether the command downloaded or executed additional content.


## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Identify the user and host, inspect the full command line, determine whether execution was expected, decode encoded content when appropriate, and check for file downloads or related process/network activity.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
