# Network Connection Anomalies

## Objective

Identify sources touching many destination ports or generating unusually high connection volume.

## SPL

```spl
index=main
| stats dc(dest_port) as Ports by src_ip
| where Ports > 20
```

Full search collection: [`../spl/07_network_connections.spl`](../spl/07_network_connections.spl)

## Investigation Approach

### Investigation Objective

Identify unusual network communication patterns by analyzing source systems, destination systems, destination ports, and connection volume.

Network activity is not automatically malicious. The purpose of the investigation is to identify communication patterns that differ from expected behavior and determine whether additional investigation is required.

### Important Network Fields

Network investigations commonly rely on several important fields:

- `src_ip` — system initiating the connection.
- `dest_ip` — system receiving the connection.
- `src_port` — source port used for the connection.
- `dest_port` — destination service port.
- `protocol` — network protocol associated with the communication.

Common destination ports include:

- `80` — HTTP
- `443` — HTTPS
- `53` — DNS
- `22` — SSH
- `25` — SMTP
- `3389` — RDP

### Network Activity Review

A useful first step is displaying important network fields:

```spl
index=main
| table _time src_ip dest_ip dest_port protocol

### Network Activity Review

A useful first step is displaying important network fields:

```spl
index=main
| table _time src_ip dest_ip dest_port protocol
```

This allows the analyst to review when connections occurred, which systems initiated them, where they connected, and which destination services were accessed.

### Destination-Port Diversity

The primary detection identifies source systems communicating with many different destination ports:

```spl
index=main
| stats dc(dest_port) as Ports by src_ip
| where Ports > 20
| sort - Ports
```

The `dc(dest_port)` calculation counts the number of distinct destination ports contacted by each source IP.

A source communicating with an unusually large number of destination ports may warrant investigation because reconnaissance or port-scanning activity can produce this pattern.

However, high destination-port diversity alone does not confirm scanning. The system role, time window, expected applications, and historical behavior should also be reviewed.

### Connection Volume Analysis

Another useful investigation is identifying systems generating large numbers of network connections:

```spl
index=main
| stats count by src_ip
| where count > 1000
| sort - count
```

High connection volume may deserve additional review, but the number alone does not establish malicious activity. Servers and other legitimate systems may normally generate large numbers of connections.

### Analyst Finding

A source system contacting many destination ports or producing unusually high connection volume may indicate activity requiring investigation.

The analyst should determine whether the communication is expected for the system and whether the behavior differs from its normal activity.

The thresholds used in this lab are investigation triggers rather than proof of compromise.

### Investigation Next Steps

- Identify the source system generating the activity.
- Determine whether the source is a workstation, server, scanner, or other expected device.
- Review the destination IP addresses.
- Identify the destination ports involved.
- Determine whether the destination services are expected.
- Review the number of distinct destination ports.
- Review the total connection volume.
- Examine when the activity occurred.
- Determine whether the behavior is normal for the source system.
- Correlate suspicious activity with firewall, DNS, endpoint, authentication, or EDR telemetry when available.

## Why it matters

This use case converts raw log events into a prioritized investigation signal so an analyst can focus on the activity most likely to require review.

## Analyst triage

Confirm whether the source is a workstation, server, scanner, management host, or other expected high-volume system. Review destination IPs, ports, protocol, and time window before escalating.

## Production consideration

This is a lab detection pattern. Field names, time windows, thresholds, and exclusions should be tuned to the organization and data source before operational use.
