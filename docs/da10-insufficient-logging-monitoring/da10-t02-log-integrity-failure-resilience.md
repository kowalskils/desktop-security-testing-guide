# Log Integrity, Retention, and Failure Resilience

| Field | Value |
| --- | --- |
| Test Case ID | DA10-T02 |
| Primary OWASP Category | DA10 - Insufficient Logging and Monitoring |
| Secondary Categories | DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, Electron, and Windows service logging |

## Scope

This test evaluates whether audit records resist unauthorized modification and remain useful across rotation, storage failures, and process restarts. It covers local files, application-owned databases, queues, and Windows event channels.

Use [DA10-T01](da10-t01-security-event-coverage-correlation.md) for event coverage and attribution, and [DA3-T04](../da3-sensitive-data-exposure/da3-t04-logs-diagnostics.md) for sensitive-data exposure. Remote forwarding and alert delivery require separate validation.

## Objective and Threat Model

Determine whether a less-trusted identity can erase, forge, redirect, or suppress required evidence, and whether loss of logging causes a documented, observable, bounded response.

Separate another standard Windows user, the application's own user, a privileged service, and an administrator. Owner-writable per-user diagnostics are not automatically a privilege-boundary failure. Explain which audit guarantee is violated. Local administrator compromise generally requires an independently protected evidence destination; a local file hash alone cannot establish tamper resistance.

## Prerequisites and Safety

- Obtain audit durability, retention, rotation, resource-limit, and failure-response requirements. Define acceptable loss and recovery delay before testing.
- Use a disposable Windows VM, synthetic records, and independent action ledger.
- Restrict mutation tests to explicitly approved application artifacts or a disposable dedicated test channel. Never clear Application, System, Security, or shared production channels.
- Use a quota-limited test destination or supported fault-injection mechanism. Never fill the OS disk, stop the Windows Event Log service, or exhaust machine-wide resources.
- Record original permissions and settings, snapshot the lab, and define stop conditions.
- Distinguish administrative fault setup from attacker capabilities. Do not report an administrator-created failure as a standard-user exploit.

## Tools

Use Process Monitor, effective-access inspection, Event Viewer, product log readers, file hashes, and independent process/resource observations. Hash stable snapshots or closed archives: legitimate appends change a live file's hash.

## Testing Methodology

### Step 1 - Map the Evidence Lifecycle

1. Identify active logs, rotations, archives, queues, temporary files, channel configuration, and cleanup jobs.
2. Record producer identities, readers, writers, retention limits, size limits, and flush/commit behavior.
3. Establish a baseline using uniquely labeled success and denial events from DA10-T01.
4. Preserve an independent record of expected events before testing loss or alteration.

Read-only examples; replace the paths and channel with approved targets:

~~~powershell
icacls 'C:\ProgramData\ExampleApp\Audit'
wevtutil gl 'Vendor-Application/Operational' /f:xml
wevtutil gli 'Vendor-Application/Operational'
~~~

Inspect channel access policy as well as file permissions. Windows Event Log access is mediated by its service; inability to edit an EVTX file directly does not establish that channel-clear or configuration operations are denied.

### Step 2 - Validate Effective Permissions

1. Inspect permissions on files, parent directories, archives, queue stores, and logging configuration.
2. Under each in-scope identity, test only approved actions against synthetic records: append, modify, truncate, rename, replace, delete, or change the destination.
3. Test parent-directory replacement separately from file write access. Review whether rotation recreates files with weaker inherited permissions.
4. For event channels, inspect effective read, publish, clear, and configuration rights. Attempt destructive channel operations only against a dedicated disposable channel with separate authorization.
5. Record actual account, operation, result, and affected guarantee. ACL text alone is not proof of effective access.
6. If a clone or test channel differs from the release configuration, document the difference and limit the conclusion accordingly.

### Step 3 - Challenge Record Boundaries

1. Submit bounded synthetic labels containing newlines, quotes, delimiters, Unicode, and control characters through normal application inputs.
2. Compare raw storage with parsed records and the investigator's viewer. Determine whether one input creates a fabricated event, replaces trusted fields, or hides neighboring records.
3. Verify trusted actor, outcome, and severity fields cannot be supplied through an untrusted message body.
4. Test malformed and oversized records below agreed resource limits. Record rejection or truncation without requiring unbounded input.
5. If the product claims cryptographic integrity, alter, remove, reorder, and replay synthetic records in an approved copy and run the actual verifier. Identify where trusted keys or checkpoints reside.

A checksum stored beside a file and writable by the same attacker does not independently authenticate it. A chain of records may detect interior changes while missing removal of its final records without a protected checkpoint. Report the tested guarantee, not merely the presence of cryptography.

### Step 4 - Verify Rotation and Retention

1. Configure supported reduced test limits in the isolated lab and record deviations from production.
2. Generate a bounded sequence sufficient to exercise rotation. Compare expected events across the active file and archives.
3. Inspect permissions on newly created artifacts and verify the intended investigator can read retained records.
4. Repeat around a normal application restart. Check partial records, duplicate entries, and missing sequence segments.
5. Test age-based cleanup only with supported fixtures or application-specific test hooks; do not change a shared host clock.
6. Explain capacity policy: Windows event retention can stop acceptance of incoming events when full, while overwrite mode replaces older events. Inspect auto-backup and available storage rather than treating retention as unlimited durability.

Configured retention is not automatically an observed retention result. If a long-duration policy cannot be exercised, report configuration evidence and the remaining test limitation.

### Step 5 - Inject One Failure at a Time

For each scenario, establish a successful baseline, introduce the approved fault, perform one synthetic audited operation, inspect application and logging outcomes, restore the destination, and repeat the operation.

| Fault in the isolated lab | Evidence required |
| --- | --- |
| Writer loses access to its test destination | Actual write error, operation outcome, independent health indication |
| Quota-limited destination reaches capacity | Bounded buffering, documented loss/backpressure behavior |
| Supported test sink becomes unavailable | Retry behavior and resource use within agreed limits |
| Disposable application process restarts with queued records | Recovered records, gaps, duplicates, and remaining queue |
| One malformed fixture reaches the parser | Neighboring valid records remain usable or failure is explicitly reported |

Do not assume a file lock produces failure; observe the actual writer error. Use supported application-local injection for event-channel failures rather than disabling the OS logging service.

The correct response depends on the operation. Some actions require a durable audit record before completion; others may continue with bounded buffering and visible degradation. Neither universally crashing the application nor silently ignoring all errors is an adequate policy.

### Step 6 - Validate Recovery and Loss Visibility

1. Reconcile the action ledger with persisted events after recovery.
2. Distinguish attempted, queued, persisted, and recovered records; a successful logging API return does not by itself prove crash-safe storage.
3. Check CPU, memory, disk, and retry behavior for unbounded growth or recursive logging failures.
4. Verify logging failure is observable through an independent channel or health mechanism, not solely through the failed destination.
5. Confirm normal permissions and logging resume after recovery without a hidden permanent disablement.
6. Retest the same fault after remediation. Remove only authorized fixtures or revert the snapshot; do not clear shared logs as cleanup.

## Evidence to Collect

Retain artifact and channel inventory, original settings, account/access results, synthetic record hashes, independent action ledger, rotation sequence, actual fault diagnostics, operation outcomes, resource observations, recovery reconciliation, and cleanup confirmation.

## Pass/Fail Criteria

### Pass

Within the stated threat model, required records and configuration resist unauthorized modification, rotation preserves the agreed evidence window, and tested failures produce bounded, visible behavior with recovery consistent with documented requirements.

### Fail

Fail for demonstrated unauthorized evidence alteration or suppression, forged trusted records, premature loss contrary to retention requirements, unbounded logging-induced resource use, or silent failure that violates the agreed audit contract. Explain the attacker capability or fault condition and actual security impact.

### Needs Further Investigation

Use when effective rights, durability requirements, failure injection, or recovery evidence cannot be established. Configuration inspection alone cannot certify runtime resilience.

## Expected Findings

- Rotated service logs inherit standard-user modification rights.
- A read-only log file can still be replaced through its writable parent directory.
- Logging failure is reported only to the same unavailable destination.
- A retry queue grows without a bound after a sink failure.
- Protected records and bounded recovery preserve the documented audit contract: expected behavior.

## Remediation Guidance

- Protect log and configuration lifecycles, including parent directories and rotation.
- Preserve structured record boundaries and separate trusted metadata from user input.
- Define retention, capacity, durability, and per-operation failure policy explicitly.
- Bound queues and retries and expose logging health independently.
- Use independently protected evidence or checkpoints for guarantees beyond local access controls.
- Add regression tests for rotation, permissions, malformed records, sink failures, and recovery.

## References

- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Microsoft: wevtutil channel configuration and retention](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [Microsoft: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
