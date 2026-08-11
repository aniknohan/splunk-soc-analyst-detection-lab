# Rare Process Hunting

## Objective

Find the least common process names as candidates for investigation.

## SPL

```spl
index=main
| rare process_name
```

Full search collection: [`../spl/06_rare_processes.spl`](../spl/06_rare_processes.spl)

## Investigation Approach

### Investigation Objective

Identify processes that appear infrequently in the environment and determine whether the activity represents legitimate software, administrative activity, or potentially suspicious execution.

A rare process is not automatically malicious. Rarity is an investigation signal that helps analysts identify unusual activity that may deserve additional review.

### SPL Analysis

Splunk's `rare` command can be used to identify the least frequently observed process names:

```spl
index=main
| rare process_name
```

The search examines the `process_name` field and returns processes that occur less frequently in the available event data.

This can help a SOC analyst move beyond commonly observed processes and focus attention on unusual executables that may otherwise be overlooked.

### Analyst Finding

A process appearing rarely in the environment should be treated as an investigation lead rather than immediate evidence of compromise.

Rare processes may include legitimate software, testing utilities, administrative tools, or uncommon applications. They may also include malware, credential-dumping tools, remote administration utilities, or other attacker-used executables.

The process name alone is therefore not enough to determine severity. The analyst should review the host, user, execution time, file location, command line, parent process, and related activity.

### Rare Process Investigation

When an uncommon process is identified, investigate the surrounding execution context.

#### Host

Determine which system executed the process.

An unusual executable appearing on a single endpoint may deserve closer inspection, particularly if the process is unexpected for that system.

#### User

Identify the user associated with the execution and determine whether running the application is expected for that account.

#### Execution Time

Review when the process executed.

Activity occurring at an unusual time, such as late at night, may increase suspicion depending on the normal behavior of the environment and user.

#### Execution Path

Determine where the executable ran from.

Common legitimate software may execute from locations such as:

```text
C:\Program Files\
```

Executables running from locations such as the following may deserve additional review:

```text
C:\Users\<user>\AppData\Local\Temp\
C:\Users\<user>\Downloads\
C:\Users\<user>\AppData\
```

Execution from these locations is not automatically malicious, but the location provides important investigative context.

#### Command Line

Review the complete command line associated with the rare process.

Command-line arguments can provide additional information about what the process attempted to do and may reveal behavior that is more significant than the process name alone.

#### Parent Process

Determine which process launched the rare executable.

For example:

```text
powershell.exe -> rare_process.exe
```

An unusual parent-child relationship may increase the priority of the investigation, particularly when PowerShell or another command interpreter launches an unexpected executable.

#### Network Activity

Determine whether the process initiated network connections.

If network activity exists, review the destination and determine whether the communication was internal or external and whether it was expected.

#### Security Tool Context

Review available antivirus or EDR alerts associated with the process when such telemetry is available.

### Investigation Next Steps

- Identify the host where the rare process executed.
- Identify the user associated with the process.
- Review the execution timestamp.
- Determine whether the execution time is normal for the user or system.
- Review the executable's full file path.
- Inspect the complete command line.
- Identify the parent process that launched the executable.
- Determine whether the process created additional child processes.
- Review any network connections associated with the process.
- Check available antivirus or EDR alerts.
- Determine whether the executable is known and expected in the environment.
- Compare the activity with normal behavior for the host and user.
- Escalate unexplained rare-process activity when the surrounding context indicates potentially malicious behavior.

### Examples Requiring Additional Review

Examples of processes or utilities that may deserve investigation when they appear unexpectedly include:

- `mimikatz.exe`
- `psexec.exe`
- `nc.exe`
- `procdump.exe`
- `certutil.exe` when used unusually
- `regsvr32.exe` when used unexpectedly
- `mshta.exe` when used unexpectedly
- Unknown or randomly named executables

The presence of these processes alone does not establish malicious activity. Their significance depends on how, where, when, and by whom they were executed.


## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Rare does not mean malicious. Check host, user, execution time, path, command line, parent process, network connections, and endpoint-security detections.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
