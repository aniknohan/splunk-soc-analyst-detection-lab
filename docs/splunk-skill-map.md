# Splunk Skill Map

This document organizes the lab into capability areas instead of presenting it as a long list of isolated commands.

## 1. Search and filtering

The foundation of the lab is event filtering with `search`, index selection, wildcards, Boolean operators (`AND`, `OR`, `NOT`), `IN`, pipes, and `where`. Result shaping is demonstrated with `fields`, `table`, `rename`, `sort`, `head`, `tail`, and `dedup`.

Regular expressions are used for two distinct purposes: `rex` extracts a field from raw text, while `regex` filters events based on a regular-expression match.

## 2. Statistical analysis and visualization

The project uses `stats` to turn many events into a summary, `chart` to compare categories, and `timechart` to analyze activity over time. `top` and `rare` surface common and uncommon values, while `eventstats` adds statistical context back to events and `streamstats` supports running calculations.

Aggregation examples include `count`, `dc()`, `values()`, `sum()`, `avg()`, `min()`, `max()`, `latest()`, and `earliest()`.

## 3. Field creation and transformation

`eval` is used to create fields, modify values, perform calculations, and combine text. Conditional logic is demonstrated with `if()` and `case()`, while `coalesce()` selects the first non-null value. The lab also covers `lower()`, `upper()`, `round()`, `substr()`, `len()`, and comparison operators.

Time handling includes `relative_time()`, `strftime()`, `strptime()`, and `now()`.

## 4. Lookups and data correlation

The lab demonstrates `lookup`, `inputlookup`, and `outputlookup`, followed by correlation methods such as `join`, `append`, `appendcols`, `transaction`, and subsearches. It also explains when a lookup is preferable to joining two searches.

## 5. Result modification and multivalue data

Result-modification commands include `fillnull`, `replace`, `appendpipe`, `foreach`, and `convert`. Multivalue workflows include `mvexpand`, `makemv`, `split()`, `mvcount()`, and `mvindex()`.

`makeresults` is used to create test events for practicing SPL functions without requiring existing indexed data, and macros are introduced as reusable SPL building blocks.

## 6. SOC analyst workflows

The final section applies SPL to operational security questions:

- Failed-login monitoring and ranking users/source IPs by failure volume.
- Successful-login review, especially after repeated failures.
- Brute-force detection using aggregated counts and thresholds.
- Suspicious PowerShell searches for encoded, hidden, bypass, and download behavior.
- Suspicious process execution, including Word spawning PowerShell.
- Rare-process hunting and contextual triage.
- Network connection review, port-scan heuristics, and high-connection-volume detection.

The corresponding detection write-ups are in the [`detections/`](../detections/) directory.
