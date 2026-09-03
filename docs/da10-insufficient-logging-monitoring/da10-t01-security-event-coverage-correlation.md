# Security Event Coverage and Cross-Process Correlation

| Field | Value |
| --- | --- |
| Test Case ID | DA10-T01 |
| Primary OWASP Category | DA10 - Insufficient Logging and Monitoring |
| Secondary Categories | DA2 - Broken Authentication and Session Management; DA5 - Improper Authorization |
| Platforms | Native Win32, .NET, Electron, Windows services, installers, and updaters |

## Scope

This test validates whether security-relevant desktop workflows produce accurate, attributable records that support investigation. It covers event generation and correlation across the UI, privileged helpers, local services, and in-scope back-end services.

Sensitive-data exclusion is covered by [DA3-T04](../da3-sensitive-data-exposure/da3-t04-logs-diagnostics.md). Detailed tamper resistance, storage failure, retention, forwarding reliability, and alert delivery require separate tests. Local event generation alone does not prove end-to-end monitoring.

## Objective and Threat Model

Determine whether an investigator can reconstruct who attempted an operation, what was targeted, which authority decided it, and what actually happened.

Consider an authenticated user attempting unauthorized actions, an unauthenticated caller, and a less-trusted process submitting identity or correlation fields. Distinguish the initiating application user from the Windows account running a service.

The test must not assume an endpoint's own logs remain trustworthy after full administrative compromise. Document where authoritative service-side evidence is required and which records are client-reported claims.

## Prerequisites and Safety

- Obtain the release build, logging configuration, event schema or catalog, and documented audit requirements.
- Use synthetic accounts, roles, tenants, and records in an isolated Windows environment.
- Agree on required event classes, expected destinations, and maximum observation delay before testing. Do not invent a universal logging latency or retention requirement.
- Select approved success and failure scenarios. Avoid account lockouts, destructive actions, real security-policy changes, or production alerts.
- Use unique, non-secret test labels and an independent action ledger containing timestamps and observed outcomes.
- Obtain only the log-read permissions needed. An elevated observation tool must not change the application's test identity.
- Keep original evidence protected and redact copies used for reporting.

## Tools

Use Event Viewer, Get-WinEvent, approved structured-log readers, Process Monitor for locating file sinks, and product-specific query tools. Runtime observation can locate a log but does not establish that its content is correct.

Windows Event Log is one supported destination, not a mandatory destination for every application. Do not equate absence from the Windows Security channel with absence of application auditing.

## Testing Methodology

### Step 1 - Map Producers and Destinations

1. Inventory the main executable, Electron renderer/main processes, services, IPC brokers, installers, updaters, and in-scope remote consumers.
2. Identify each producer's provider/channel, file, database, or remote destination. Record enabled levels, filters, schema version, and normal production settings.
3. Distinguish durable audit records from debug output, console messages, and traces that exist only during an active capture session.
4. Identify which component makes each security decision and which component reports the final operation result.
5. Record clock sources, time zones, and known offsets. Do not change a shared machine's clock for this test.

For an approved custom channel, replace the example name and inspect its configuration without modifying it:

~~~powershell
Get-WinEvent -ListLog 'Vendor-Application/Operational' |
    Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes
~~~

### Step 2 - Define the Event Coverage Matrix

Adapt these candidates to the product threat model and requirements. Record exclusions and rationale; not every product supports every operation.

| Workflow | Controlled trigger | Expected audit distinction |
| --- | --- | --- |
| Authentication | Synthetic account succeeds, then fails once | Successful identity establishment versus rejected attempt |
| Session lifecycle | Logout, account switch, expiration | Ended session versus continuing or newly established session |
| Authorization | Allowed and denied access to a synthetic record | Initiator, target, decision, and reason category |
| Privileged helper | Approved and rejected IPC request | Caller identity versus executing service identity |
| Security settings | Authorized change and denied change | Setting identity, decision, and actual resulting state |
| Sensitive operation | Synthetic export or administrative action | Requested action versus completed, failed, or canceled result |
| Update trust | Approved lab update and invalid test package | Accepted update versus integrity/policy rejection |

For each row, specify the producer, event type, required fields, destination, delay allowance, and expected record relationship. An operation may legitimately produce several records; do not demand exactly one record without a product contract.

### Step 3 - Execute and Reconcile

1. Record the start time and initial state. Perform one matrix action using a fresh test label where the product permits it.
2. Independently verify the outcome: UI status alone may not show whether a service completed or rolled back an action.
3. Wait within the agreed observation window, then query the documented destination. Repeat for a denial and an ordinary failure.
4. Match the actual event sequence to the action ledger. Distinguish request received, authorization decision, work started, and final outcome.
5. Check whether an apparent success was logged before a transaction subsequently failed. A request-accepted record must not be interpreted as completed work.
6. Repeat relevant cases after normal restart and under the release's normal logging level. Evidence that exists only with extra debug logging does not satisfy a production audit requirement.

Example bounded Windows query, using the same PowerShell session around the manual action:

~~~powershell
$auditStart = Get-Date
# Perform one approved test action now.
$auditEnd = Get-Date
# Query after the agreed logging delay, using the action window.
Get-WinEvent -FilterHashtable @{
    LogName = 'Vendor-Application/Operational'
    StartTime = $auditStart
    EndTime = $auditEnd
} -ErrorAction Stop |
    Select-Object TimeCreated, ProviderName, Id, RecordId, UserId, Message
~~~

Record errors rather than hiding them. A missing channel or access denial is not proof of a missing application event. If emission is delayed, expand the query through the agreed deadline and correlate using the action label or product operation ID; emission time may differ from action time.

### Step 4 - Validate Identity and Event Meaning

1. Compare initiator, executing identity, action, target, decision, final outcome, timestamp, and reason category with the independent ledger.
2. Test two application users, including an account switch in one desktop session. Look for stale user attribution and cross-tenant target confusion.
3. Inspect privileged-helper records. A service running as SYSTEM should not cause all initiating users to become indistinguishable where attribution is required.
4. Treat failed-login usernames as claimed identities until authentication succeeds. Do not log credentials to make failures attributable.
5. Through supported test inputs, submit a different claimed username or correlation label. Verify the authoritative record does not mistake client-supplied identity for a verified principal.
6. Confirm identifiers are stable enough for investigation without exposing bearer tokens, passwords, or unnecessary record content. Apply DA3-T04 to confidentiality checks.

Windows event system metadata can identify the event provider and execution context, but the application may need additional fields to identify the business user and operation. Inspect structured event data as well as the rendered message; presentation or localization issues must not be mistaken for absent raw data.

### Step 5 - Follow Cross-Process Operations

1. Trace one desktop-to-service action and, where authorized, its back-end result.
2. Determine how operation or activity IDs connect records across boundaries. Record any translation between IDs.
3. Run two overlapping synthetic operations, then a retry or cancellation. Confirm that an investigator can distinguish concurrent work, repeated delivery, and a new action.
4. Verify a canceled UI request is not assumed to cancel already-running service work. Compare the final state with the service's completion record.
5. Check records after a normal process restart. Process IDs alone are insufficient long-term correlation identifiers because they can be reused.
6. Treat event record numbers as destination-local evidence, not a global ordering across providers or machines. Document clock uncertainty and use operation relationships where timestamps alone are ambiguous.

Correlation identifiers are investigative data, not authorization credentials. Their presence does not prove that a caller is entitled to perform an operation.

### Step 6 - Test Investigative Usability

1. Give a reviewer the sanitized records and schema, without the action ledger.
2. Ask the reviewer to reconstruct actor, target, decision, final outcome, and sequence for the selected workflows.
3. Compare the reconstruction with the ledger. Record missing fields, ambiguous outcomes, and correlations requiring unsupported assumptions.
4. Verify that required data is accessible using the intended investigator role, not only a developer's privileged debug session.
5. If a remote destination is required, establish whether the same event is visible there. Report remote access or ingestion uncertainty separately; this step does not certify forwarding reliability or alerting.

### Step 7 - Retest and Preserve Evidence

Repeat failing rows after remediation, together with positive controls and the account-switch/concurrency cases. Export only the approved test scope, retain structured fields, and hash evidence files. Do not clear shared logs as cleanup; remove synthetic application records only through approved procedures.

## Evidence to Collect

Retain the producer/destination map, release and configuration, event coverage matrix, action ledger, accounts and roles, bounded queries, raw event fields, observation delays, cross-process correlations, reviewer reconstruction, and retest results. Record inaccessible destinations and untested workflows explicitly.

## Pass/Fail Criteria

### Pass

Required events are available under normal release settings within the agreed window, accurately identify actors and outcomes, and permit reconstruction of the tested workflows without unnecessary sensitive data. State scope; generation coverage does not establish resistance to tampering or reliable alert delivery.

### Fail

Fail when a required security event is demonstrably absent, attributed to the wrong principal, misleading about the completed outcome, or impossible to correlate across a required boundary. Confirm the correct destination, read access, filters, and emission window before reporting absence.

### Needs Further Investigation

Use when audit requirements, destination access, event timing, schema, or independent operation outcome cannot be established. Document missing requirements as a design gap rather than inventing evidence of a runtime failure.

## Expected Findings

- A denied IPC action appears in debug output but not the required production audit trail.
- An account switch leaves later exports attributed to the previous user.
- A service records successful completion when it only accepted a request.
- Concurrent operations cannot be separated because all records share a process-level label.
- Structured records permit accurate reconstruction without logging authentication secrets: expected behavior.

## Remediation Guidance

- Define product-specific event contracts at security decision and operation-completion points.
- Preserve verified initiator identity separately from the executing service account and client claims.
- Use stable event schemas and explicit attempt, decision, and completion semantics.
- Carry non-secret operation identifiers across process boundaries and preserve retry relationships.
- Make required audit events available in normal release configurations.
- Automate matrix-based regression checks, including account changes, denials, failures, and concurrent actions.

## References

- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Microsoft: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Microsoft: Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [Microsoft: Windows event system properties](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype)
