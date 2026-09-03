# Event Forwarding and Alert Validation

| Field | Value |
| --- | --- |
| Test Case ID | DA10-T03 |
| Primary OWASP Category | DA10 - Insufficient Logging and Monitoring |
| Secondary Categories | DA6 - Security Misconfiguration; DA7 - Insecure Communication |
| Platforms | Windows desktop applications, forwarding agents, Windows Event Forwarding, collectors, and monitoring integrations |

## Scope

This test follows a security event from the desktop through collection, parsing, detection, and an approved notification destination. It includes delivery gaps, recovery, rule boundaries, and monitoring health.

Use [DA10-T01](da10-t01-security-event-coverage-correlation.md) to establish event generation and [DA10-T02](da10-t02-log-integrity-failure-resilience.md) for local integrity and storage resilience. A local event, healthy agent, or collector acknowledgment alone does not establish successful detection.

## Objective and Threat Model

Determine whether required events reach the authorized destination with usable meaning, whether detection rules identify the intended behavior, and whether broken monitoring becomes visible.

Consider a disconnected endpoint, misconfigured filter, malformed record, less-trusted event sender, and attacker-controlled application fields. Distinguish authenticated transport identity from the truth of a record's content: an authenticated compromised endpoint can still report misleading activity.

## Prerequisites and Safety

- Obtain the event contract, forwarding configuration, parser version, detection rules, suppression rules, notification routes, and expected owners.
- Agree on delivery and alert deadlines, permitted event loss, duplicate handling, and recovery targets. Define rule thresholds and observation windows before execution.
- Use synthetic users and records in a lab endpoint and approved collector/test tenant.
- Route notifications to a controlled test destination. Disable containment, account blocking, ticket escalation, paging, and other automated actions in the test integration.
- Obtain explicit approval before any test can reach an operational monitoring team. Documentation testing does not authorize real incident response.
- Restrict disruptions to a disposable agent or test connection. Do not stop shared collectors, disable the host firewall globally, or change production subscriptions.
- Preserve normal configuration and record every test-only override. If remote access is unavailable, report partial coverage instead of assuming delivery.

## Tools

Use application event queries, forwarding diagnostics, collector searches, parser output, rule evaluation history, and test notification receipts. Maintain an independent ledger with unique non-secret operation labels and timestamps.

## Testing Methodology

### Step 1 - Map the Complete Route

1. Identify the producer, local channel or file, agent/subscription, transport, collector, parser/index, rule, and final test destination.
2. Record source selection, event filters, exclusions, batching, retry policy, buffering, and existing-event behavior.
3. Identify the credentials and identities used at each boundary without exporting secrets.
4. Record event time, receipt time, index availability, rule evaluation, and notification time separately. Measure clock offsets or state uncertainty; do not assume different hosts' clocks agree.
5. Define the expected accountable owner for a detection and for a collection failure.

For Windows Event Forwarding (WEF), inspect the approved subscription on the collector:

~~~powershell
wecutil gs 'DSTG-Lab-Subscription' /f:xml
wecutil gr 'DSTG-Lab-Subscription'
~~~

These are inspection commands, not setup commands. A missing service or inaccessible collector is a diagnostic limitation, not permission to reconfigure it.

WEF selects existing events; it does not enable event generation or grant source-channel access. Inspect subscription filters and read-existing-events policy. Its offline buffer is the source event log, so overwritten source records cannot be recovered merely by reconnecting. A heartbeat is not proof that all required events arrived.

### Step 2 - Establish End-to-End Positive Controls

1. Generate one approved event through the actual desktop workflow from DA10-T01.
2. Record the source event's operation label, source identity, provider/schema, action, outcome, and timestamp.
3. Locate the corresponding raw collector record and normalized record. Save the bounded queries and their time ranges.
4. Compare required fields through every transformation, including user, device, tenant, outcome, severity, and operation identifier.
5. Verify that Unicode, structured fields, and localization do not silently change rule-relevant meaning.
6. Follow the matching rule evaluation into the test notification and confirm the recipient can retrieve the supporting evidence using the intended role.

If a manually injected fixture is needed, label it as a parser/rule test. It does not replace proof that the desktop producer and forwarding path work.

### Step 3 - Validate Transport and Source Boundaries

1. Inspect authentication, destination validation, encryption, and sender authorization for each hop.
2. In a dedicated lab setup, verify rejection of an unapproved sender or invalid destination identity using synthetic credentials.
3. Confirm sender-supplied fields cannot make a record appear to originate from another trusted device or tenant without being marked as unverified.
4. Check that credentials and sensitive event content do not reach an unintended destination on failure or fallback.
5. Use [DA7-T02](../da7-insecure-communication/da7-t02-tls-certificate-proxy.md) for applicable TLS tests. For WEF, assess the actual authentication and message protection: an HTTP URL alone is not proof of plaintext when authenticated message encryption is used.

Report inability to test a boundary separately from configuration concerns. Transport success does not establish authorization to view another tenant's collected events.

### Step 4 - Exercise Detection Boundaries

Record the expected result before running each fixture:

| Controlled case | Expected evaluation |
| --- | --- |
| Pattern meeting the documented threshold | Matching detection within the agreed window |
| Otherwise similar benign event | No matching detection from that rule |
| Counts immediately below and at the configured threshold | Exact boundary behavior, according to the rule's operator |
| Similar actions by different users/devices | Correct grouping, without accidental cross-identity aggregation |
| Duplicate delivery of one event | Documented deduplication or counting behavior |
| Event arriving late or out of order | Documented event-time versus ingestion-time handling |
| Same pattern outside a suppression scope | Not silently suppressed by an unrelated exception |

1. Use safe synthetic fixtures rather than repeated real login failures that could lock accounts.
2. Reset only isolated test-rule state when necessary and record the reset. Otherwise, earlier fixtures may contaminate later counts.
3. Inspect parsing and evaluation history when a result differs. A missing alert may be a collection, schema, rule, schedule, or routing failure.
4. Document any reduced test threshold; separately verify the production rule configuration. A modified rule cannot prove the original threshold works.
5. Ensure alert text describes the observed behavior and does not claim an incident or exploit was confirmed solely because a pattern matched.

### Step 5 - Interrupt and Reconcile Delivery

1. Record a healthy baseline, then briefly interrupt only the approved test route.
2. Generate a bounded, uniquely labeled event sequence. Record which events remain in local storage and the expected replay behavior.
3. Restore the route and compare source, collector, normalized, and detection records.
4. Identify missing, repeated, delayed, and incorrectly reordered records. Do not assume a delivery guarantee such as exactly-once unless the integration defines and demonstrates it.
5. Verify duplicate replay does not generate unintended repeated incidents, and delayed records are evaluated or excluded according to documented policy.
6. Check the backlog clears within the agreed target without unbounded resource use.
7. If testing source rollover during an outage, use a disposable test channel with bounded capacity. Record the unrecoverable gap and how the wider monitoring design detects it.

### Step 6 - Test Monitoring Health and Notification

1. Verify the isolated outage produces the expected source-health or ingestion-lag indication, independently of the unavailable route where required.
2. Check a parser-rejected synthetic record is visible to operators rather than silently discarded.
3. Deliver a test alert and confirm actual receipt, accessible evidence, correct ownership, and acknowledgment behavior where in scope.
4. In an approved test destination, simulate notification failure and inspect retry or alternate routing without contacting real recipients.
5. Distinguish alert creation, notification delivery, acknowledgment, and response. A console alert does not prove any person received it.
6. Confirm recovery clears stale health warnings without concealing unresolved loss.

### Step 7 - Retest and Restore

Repeat failed fixtures after remediation, including the benign control and reconnection sequence. Restore test-only settings, remove synthetic credentials, and close or label only test notifications. Preserve approved evidence; do not clear shared event stores or detection history.

## Evidence to Collect

Retain route and trust-boundary inventory, sanitized configuration/rule versions, independent fixture ledger, source and collector records, normalized fields, evaluation results, timing measurements, test receipts, outage reconciliation, health indications, and cleanup confirmation.

## Pass/Fail Criteria

### Pass

For the documented workflows, required records arrive with usable identity and meaning, rules pass positive and negative controls, authorized test notifications are received within agreed limits, and interruptions recover with observable handling of gaps and duplicates.

### Fail

Fail for demonstrated silent loss contrary to the monitoring contract, altered critical fields, unauthorized source attribution, missed required detections, incorrect grouping or suppression, failed required notification, or an undetected broken route. Identify the failing stage and scope rather than treating every failure as a desktop logging defect.

### Needs Further Investigation

Use when collector access, parser behavior, rule state, deadlines, or notification receipts cannot be established. A configuration review or an agent heartbeat alone is insufficient for an end-to-end pass.

## Expected Findings

- A subscription omits a new application event type although local generation succeeds.
- A parser drops the actor field, causing unrelated users' activity to aggregate.
- Offline replay generates repeated incidents for the same operation.
- A rule matches but its notification route has no working recipient.
- A monitoring heartbeat stays healthy while required events are filtered out.

## Remediation Guidance

- Version and test producer schemas, collection filters, parsers, and rules together.
- Preserve source identity and operation relationships through transformations.
- Protect each transport boundary and restrict senders and readers appropriately.
- Size buffering and recovery against the documented outage budget.
- Define deduplication, late-event, suppression, and notification behavior explicitly.
- Monitor collection and parsing health independently of ordinary business events.
- Maintain safe end-to-end fixtures and controlled test notification routes.

## References

- [Microsoft: Windows Event Forwarding for intrusion detection](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [Microsoft: Windows Event Collector](https://learn.microsoft.com/en-us/windows/win32/wec/windows-event-collector)
- [Microsoft: wecutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil)
- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
