# BOTS v1 | Network alert triage and endpoint correlation

**Case BOTS-001** · Splunk Enterprise · Public training telemetry · Tier 1 → Tier 2

A firewall IPS alert reports a possible Windows reverse shell. Triage the alert, identify the target from endpoint telemetry, and decide whether the case merits escalation. Review scanner traffic separately to establish alert volume and avoid conflating two investigations.

## Start from scratch

1. Open the [official Splunk BOTS v1 repository](https://github.com/splunk/botsv1). Follow its installation and add-on instructions for a compatible isolated lab instance. Keep the package and dataset outside this repository.
2. In Splunk, open **Search & Reporting**, set the time picker to **All time**, and use **No Event Sampling**. Run the readiness search below. Confirm the index name and record your Splunk version, dataset edition, and time zone. Historical timestamps require an all-time or historical time range.
3. Run each search in [SPL search pack](searches.md) individually. Start with inventory and inspect the raw event whenever a field is missing. Adapt field aliases to what your installation extracts.
4. Optional dashboard setup. Create a **Classic Dashboard**, open **Edit → Source**, paste [dashboard.xml](dashboard.xml), and save. Its three panels show FortiGate signatures, Suricata severity, and firewall reverse-shell candidates. Use the individual searches for endpoint pivots.
5. Complete the [case report](case-report.md) with your observed results and screenshots.

```spl
index=botsv1 earliest=0
| stats count min(_time) as first_seen max(_time) as last_seen by sourcetype
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

If this returns zero rows, check index permissions and the dataset installation. If FortiGate, Suricata, or Windows XML telemetry is missing, inspect the dataset edition and source types before attempting correlation. Exact totals depend on the edition and extraction configuration.

## Investigation decision

A firewall signature is a lead. Establish direction, target identity, and timing. Look for corroborating network events and process activity on the target. Firewall detection alone cannot establish command execution, an active shell, or compromise. If the network and endpoint evidence converge, escalate for validation and preserve the raw events. Record alternative explanations and coverage gaps if they do not.

### Tools

`Splunk Enterprise` · `SPL` · `FortiGate UTM` · `Suricata` · `Windows XML / Sysmon`

### Scope

This exercise uses historical BOTS v1 training data. IP addresses and signatures are search pivots inside Splunk. No live scanning or connections to those addresses are needed. The searches and dashboard are supplied as lab materials. Results and screenshots should come from your own Splunk run.
