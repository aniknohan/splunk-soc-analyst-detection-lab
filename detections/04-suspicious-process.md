# Suspicious Process Execution

## Objective

Detect the lab example of Microsoft Word launching PowerShell.

## SPL

```spl
index=main parent_process="winword.exe" process_name="powershell.exe"
```

Full search collection: [`../spl/05_suspicious_process_execution.spl`](../spl/05_suspicious_process_execution.spl)

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Review parent/child process context, command line, user, host, execution path, and activity immediately before and after the process launch.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
