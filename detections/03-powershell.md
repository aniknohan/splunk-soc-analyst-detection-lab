# Suspicious PowerShell Activity

## Objective

Find PowerShell executions with common suspicious command-line patterns such as encoding, hidden windows, execution-policy bypass, or download behavior.

## SPL

```spl
index=main process_name="powershell.exe"
| search Invoke-WebRequest OR DownloadFile OR Net.WebClient
```

Full search collection: [`../spl/04_powershell_detection.spl`](../spl/04_powershell_detection.spl)

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Identify the user and host, inspect the full command line, determine whether execution was expected, decode encoded content when appropriate, and check for file downloads or related process/network activity.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
