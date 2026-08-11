# SOC Investigation Notes

## Failed logins

High failed-login volume is a signal to investigate, not proof of compromise. The lab recommends checking who is being targeted, which source IP is generating the failures, how many failures occurred, and whether a successful login followed. Legitimate explanations can include password mistakes, locked accounts, expired passwords, and outdated service-account credentials. Suspicious explanations include brute force, password spraying, credential stuffing, and unauthorized access attempts.

## Successful logins

A successful login can be normal or suspicious depending on context. Review successful authentications after repeated failures, from new IP addresses, from unusual locations, outside normal business hours, or in combinations that could suggest impossible travel. Correlate with the user, host, source IP, time, and earlier authentication activity.

## Brute-force triage

The source lab uses a simple threshold example: aggregate failed logins by source IP and investigate sources with more than 10 failures. It also emphasizes that thresholds differ by organization. Before escalating, determine whether the IP is internal or external, whether it has been seen before, which accounts were targeted, whether privileged accounts were involved, and whether a success followed the failures.

## PowerShell triage

PowerShell is legitimate administrative software, so process presence alone is not enough. The lab focuses on command-line indicators such as `-EncodedCommand`, `-enc`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `-w hidden`, `Invoke-WebRequest`, `DownloadFile`, `Net.WebClient`, and `IEX`. Investigation should identify the user, host, command line, whether the execution was expected, and whether the command downloaded content.

## Suspicious process execution

Process relationships can reveal attacker behavior. The lab highlights `winword.exe -> powershell.exe` as a suspicious parent/child pattern. Analysts should examine the parent process, child process, command line, user, host, execution location, and nearby activity before making a determination.

## Rare-process hunting

A rare process is unusual, not automatically malicious. The recommended triage questions are: Which host ran it? Which user executed it? When? From what path? What command line was used? What parent launched it? Did it make network connections? Did EDR or antivirus detect it? Running from user-writable locations such as Temp, Downloads, or AppData deserves closer inspection.

## Network connections

For network investigations, focus on source/destination IP, destination port, protocol, and time. The lab demonstrates a distinct-destination-port heuristic for possible port scanning and a high-volume connection heuristic for systems generating unusually large numbers of network events. Both require environmental context because scanners, servers, management tools, and other legitimate systems can naturally produce high counts.
