# Analyst case report | BOTS-001

**Status** · Worksheet for VM validation

| Field | Record from your run |
| --- | --- |
| Analyst, date and time zone | |
| Dataset edition and Splunk version | |
| Initial severity and rationale | |
| Firewall event time, signature and action | |
| Source and destination address and port | |
| Endpoint name and identification evidence | |
| Related process, user and process GUID | |
| Final disposition and evidence gaps | |

## Timeline

| Event time (UTC) | Source | Observation | Evidence reference |
| --- | --- | --- | --- |
| | FortiGate UTM | Initial signature and action | |
| | Suricata | Matching network event, if found | |
| | Windows XML | Endpoint and process association, if found | |

## Screenshot checklist

1. **01-source-inventory.png** — source types and event counts with query and time range visible.
2. **02-firewall-signature.png** — reverse-shell signature with expanded raw event and action.
3. **03-network-pivot.png** — narrowed Suricata search and the fields used to assess correlation.
4. **04-endpoint-attribution.png** — raw XML evidence linking the internal address to a hostname or process.
5. **05-dashboard.png** — saved dashboard with source-specific counts and reverse-shell candidates.

Save the relevant raw event excerpts separately. Record the search, time range, event time, field mapping, and evidence filename. If a search has no match, document the scope and what is missing.

## Handoff

Summarize what the firewall detected, what independent telemetry corroborates, and what is still unknown. Request Tier 2 review if the firewall lead is supported by matching endpoint activity or other evidence of execution. Where endpoint visibility is incomplete, route the unresolved alert for validation and state the coverage gap. Keep the scanner findings separate unless a common endpoint, time window, and event sequence support a connection.
