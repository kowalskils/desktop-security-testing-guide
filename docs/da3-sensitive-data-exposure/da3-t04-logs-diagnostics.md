# Sensitive Data in Logs, Temporary Files, Clipboard, and Diagnostic Artifacts

| Field | Value |
| --- | --- |
| Test Case ID | DA3-T04 |
| Primary OWASP Category | DA3 - Sensitive Data Exposure |
| Secondary Categories | DA5 - Improper Authorization; DA6 - Security Misconfiguration; DA10 - Insufficient Logging and Monitoring |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test determines whether a Windows desktop application exposes sensitive data through operational and diagnostic artifacts. It covers application and Windows event logs, debug output, temporary files, clipboard content, crash reports, memory dumps, telemetry queues, support bundles, exported diagnostics, screenshots, and artifacts created by installers, updaters, helper processes, and embedded browser components.

In-scope data includes credentials, tokens, session identifiers, keys, connection strings, personal or regulated records, sensitive document content, full request or response bodies, internal infrastructure details, and security-control configuration.

Logging and diagnostics are necessary security and support capabilities. The objective is not to remove useful evidence, but to ensure that sensitive data is minimized, redacted, access-controlled, retained appropriately, and transmitted only to approved destinations.

## Objective

Determine whether:

- Sensitive values are written to logs, traces, console output, temporary files, or event records.
- Copy operations leave high-value data in the Windows clipboard beyond the intended workflow.
- Crash handlers and Windows Error Reporting collect memory or files containing secrets.
- Support bundles include more data than their stated purpose requires.
- Diagnostic artifacts are readable, writable, replaceable, or uploadable by unintended identities.
- Redaction is consistent across normal, error, debug, offline, and retry paths.
- Cleanup, retention, consent, and transmission behavior match documented policy.
- User-controlled input can forge, truncate, or inject misleading log entries.

## Threat Model

The test considers another local user, same-user malware, a help-desk or support recipient with excessive access, an attacker who obtains a support archive or crash queue, and an attacker who injects content into logs to conceal activity or mislead investigation.

Potential impacts include credential theft, session replay, disclosure of regulated data, cross-user exposure, unauthorized remote access, loss of audit integrity, and unintended transmission to vendors or third parties.

## Prerequisites and Safety

- Use isolated Windows test systems and synthetic accounts, secrets, and records.
- Create unique markers for credentials, tokens, personal records, document content, and attacker-controlled log input.
- Record application, Windows, process, crash-handler, telemetry, and support-tool versions.
- Obtain authorization before intentionally triggering failures or creating diagnostic bundles.
- Do not cause destructive crashes, denial of service, or external telemetry transmission outside the approved environment.
- Treat logs, dumps, screenshots, and bundles as sensitive evidence.
- Disable or redirect outbound upload only through supported test configuration; record any difference from production behavior.

## Test Data Design

| Purpose | Example Marker |
| --- | --- |
| Credential | `DSTG-LOG-PWD-71A4-NOTREAL!` |
| Token | `DSTG-LOG-TOKEN-38C2-SYNTHETIC` |
| Personal record | `DSTG-LOG-PII-94B7` |
| Document | `DSTG-TEMP-DOC-26F8` |
| Log injection | `DSTG-ENTRY-START%0D%0AFORGED-EVENT` |

Use different values for each workflow and repeat so stale matches can be attributed accurately.

## Tools

- **Process Monitor** for file, Registry, process, and network-adjacent diagnostic activity.
- **Event Viewer, `wevtutil`, and PowerShell** for Windows event channels and access checks.
- **Sysinternals Strings** for controlled searches in dumps and binary artifacts.
- **Process Explorer and VMMap** for process roles and crash-handler relationships.
- **Archive and format-aware viewers** for support bundles, structured logs, databases, and telemetry queues.
- **Network capture or an approved intercepting proxy** for authorized verification of diagnostic uploads.
- **`icacls`, AccessChk, and PowerShell** for artifact and directory permissions.

## Testing Methodology

### Step 1 - Establish the Diagnostic Surface

Identify and record:

- Application, audit, debug, trace, installer, updater, service, and plug-in logs
- Windows Application, System, Security, and custom event channels used by the product
- Console, `OutputDebugString`, ETW, and structured diagnostic output
- `%TEMP%`, `%LOCALAPPDATA%\Temp`, service-profile temp paths, product caches, and staging directories
- Windows Error Reporting, vendor crash handlers, Electron/Chromium crash reporting, and dump folders
- Telemetry queues, retry stores, offline reports, screenshots, and support-bundle generators
- Upload destinations, consent prompts, retention settings, and redaction configuration

Capture Process Monitor activity during launch, authentication, sensitive operations, errors, logout, update, bundle generation, and exit.

### Step 2 - Exercise a State Matrix

For each marker, exercise:

1. Data entry before submission
2. Successful authentication or sensitive operation
3. Validation failure and authentication failure
4. Network timeout, server error, parsing error, and retry
5. Logout, account switch, and session timeout
6. Debug or verbose logging mode when it is supported and in scope
7. Application update, repair, and uninstall
8. Support-bundle generation and crash-report preparation

Error paths often log more context than successful paths. Test both without forcing unsafe system-wide failures.

### Step 3 - Inspect Application and Event Logs

1. Search all discovered logs and event channels for exact markers and sensitive field names.
2. Review current files, rotations, archives, compressed logs, and retained previous versions.
3. Record event provider, channel, event ID, level, process, user, timestamp, and field containing each match.
4. Verify permissions to read, append, overwrite, rename, delete, clear, or alter logging configuration.
5. Determine whether another application or Windows user can read the tested user's data.
6. Check whether low-privileged input can create forged lines, fields, delimiters, or terminal-control content.

Example export for an approved custom channel:

```powershell
wevtutil epl "Vendor/Application" ".\Vendor-Application.evtx"
Get-WinEvent -LogName "Vendor/Application" -MaxEvents 200 |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
```

Do not copy complete production event logs into an assessment environment.

### Step 4 - Inspect Temporary and Intermediate Files

1. Record temp paths resolved for every relevant user and service identity.
2. Monitor creation, permissions, naming, content, close, rename, and deletion of temporary files.
3. Search autosave files, extracted attachments, print/export intermediates, renderer caches, updater staging, and decompressed content.
4. Verify whether files remain after success, cancellation, failure, crash, logout, and reboot.
5. Test whether another user can read or replace a temporary file before the application consumes it.
6. Check for predictable names, unsafe shared directories, and symbolic-link or path-redirection exposure when applicable.

The Windows temporary-path API returns a path but does not by itself verify existence or adequate access. The application must create sensitive temporary content with appropriate permissions and collision-resistant semantics.

### Step 5 - Validate Clipboard Behavior

1. Copy each supported sensitive data type through the application's UI.
2. Enumerate the formats placed on the clipboard; inspect text, HTML, rich text, images, file lists, and application-specific formats.
3. Determine whether concealed values such as passwords, recovery codes, private keys, or masked fields can be copied.
4. After the documented timeout, logout, account switch, view closure, and application exit, determine whether the marker remains retrievable.
5. Verify whether clipboard history or cross-device synchronization changes the exposure, when those features are part of the product threat model.
6. Confirm that clearing behavior does not destroy unrelated user clipboard content without a documented product decision.

Clipboard access is generally a same-session boundary. Report the required attacker context and do not imply remote compromise without evidence.

### Step 6 - Inspect Crash Reports and Dumps

1. Identify Windows Error Reporting `LocalDumps` and product-specific crash settings.
2. Record dump type, count, folder, ACL, owning identity, and upload behavior.
3. Trigger only a safe, approved application failure or use a vendor-provided diagnostic path.
4. Search the report, dump, metadata, screenshots, attachments, and queued upload for synthetic markers.
5. Determine whether the dump contains private read/write memory and whether a smaller diagnostic form would meet the support need.
6. Verify local retention, rotation, consent, encryption, destination, transport, and server-side access assumptions.

Windows Error Reporting defaults local user-mode dumps to `%LOCALAPPDATA%\CrashDumps` when configured. A custom dump folder must have sufficient and appropriate ACLs; writability for the crashing process must not become broad read access.

### Step 7 - Inspect Support Bundles

1. Generate a bundle through the normal UI and command-line workflow, if both exist.
2. Inventory every included file, nested archive, Registry export, event log, dump, database, configuration file, screenshot, and system-information record.
3. Compare the bundle against the UI disclosure and product documentation.
4. Search all expanded content for markers, credentials, tokens, keys, personal data, document paths, usernames, and unrelated application information.
5. Verify redaction before archive creation, not only in a viewer or upload screen.
6. Check archive permissions, encryption, password delivery, local retention, upload destination, and deletion after submission.
7. Test cancellation and failed-upload paths for residual bundles and retry queues.

### Step 8 - Validate Redaction and Structured Logging

For each sensitive field:

1. Compare success, validation-error, exception, retry, debug, and offline paths.
2. Test values containing quotes, separators, newlines, control characters, long input, and Unicode.
3. Confirm that redaction operates on the structured field rather than unreliable substring replacement.
4. Verify that secrets are not split across multiple fields or partially exposed through prefixes, suffixes, headers, URLs, or exception objects.
5. Ensure correlation identifiers remain useful without becoming bearer credentials.

### Step 9 - Validate Permissions and Retention

1. Review effective ACLs for log, temp, dump, telemetry, and bundle directories and files.
2. Test read/write/delete access with a second standard Windows user.
3. Verify rotation limits, retention periods, cleanup after logout/uninstall, and handling when deletion fails.
4. Confirm that privileged logs cannot be cleared or forged by the application user unless explicitly required.
5. Verify that remote collectors and support recipients receive only the minimum necessary data.

### Step 10 - Document and Clean Up

Record artifact paths, hashes, owners, ACLs, marker matches, workflow states, redaction results, retention, destinations, and attacker prerequisites. Restore settings, remove synthetic dumps and bundles, and follow the approved evidence-disposal procedure.

## Evidence to Collect

- Diagnostic-surface inventory and Process Monitor capture
- Log providers, channels, files, rotation, configuration, and effective ACLs
- Temporary paths, filenames, lifecycle, hashes, owners, and permissions
- Clipboard formats, marker presence, clearing event, and attacker context
- Crash handler, dump type, folder, content, retention, consent, and destination
- Expanded support-bundle inventory and redaction comparison
- Marker matches with exact workflow and state
- Cross-user access, log-injection, tamper, and cleanup results
- Network destination and minimum necessary upload evidence when tested
- Cleanup and evidence-disposal record

## Pass/Fail Criteria

### Pass

The test passes when operational and diagnostic artifacts exclude unnecessary sensitive values, apply consistent structured redaction, enforce appropriate access, retain data only as required, and transmit it only with documented controls to approved destinations. Clipboard and temporary content must not outlive their justified workflow, and audit integrity must resist unintended modification.

### Fail

The test fails when:

- Credentials, reusable tokens, private keys, protected records, or sensitive content are logged or bundled without necessity and effective protection.
- Another unintended user can read diagnostic artifacts or alter security-relevant logs.
- Temporary files or clipboard content expose high-value data beyond the intended workflow.
- Dumps, screenshots, telemetry queues, or support bundles include sensitive data without adequate disclosure, access control, retention, or transmission safeguards.
- User input can forge or corrupt security-relevant log records.
- Redaction applies only to successful paths while exceptions, debug output, retries, or offline queues expose the original value.

Severity should reflect data sensitivity, reusability, access required, affected users, destination, retention, audit impact, and scale.

### Needs Further Investigation

Use this outcome when a candidate value's sensitivity, validity, ownership, destination, redaction state, or effective access cannot be established. Do not treat every identifier, path, stack trace, or crash record as a confirmed exposure.

## Expected Findings

### Secure or Expected Conditions

- Logs use structured fields and exclude credentials, tokens, keys, and unnecessary record content.
- Sensitive temporary files are private, collision-resistant, and promptly removed.
- High-value fields cannot be copied, or clipboard data is cleared according to documented behavior.
- Dumps and bundles are minimized, protected, disclosed, retained, and transmitted appropriately.
- Event and audit logs have permissions consistent with their integrity requirements.

### Potential Findings

- Authorization headers, passwords, tokens, connection strings, or personal records appear in logs.
- Exception objects or request bodies bypass normal redaction.
- Temporary exports and attachments remain readable after logout or failure.
- Clipboard history retains recovery codes or decrypted content.
- Full dumps and support bundles expose process memory, databases, Registry exports, or unrelated user data.
- Standard users can overwrite or clear privileged audit artifacts.

## Remediation Guidance

- Define an allowlist of fields permitted in each log and diagnostic channel.
- Apply structured redaction at the source before formatting, persistence, queuing, or transmission.
- Never log credentials, bearer tokens, private keys, or complete regulated records.
- Use private temporary directories and secure file-creation semantics; remove artifacts on success and failure.
- Restrict copy operations for high-value secrets and document any clipboard-clearing behavior.
- Minimize dump type and support-bundle content; require informed consent where appropriate.
- Protect local queues, dumps, and bundles with least-privilege ACLs and suitable encryption.
- Authenticate diagnostic destinations and enforce retention and access controls end to end.
- Sanitize untrusted log fields and preserve event boundaries to prevent injection.
- Add automated tests for redaction across success, error, debug, retry, and offline paths.

## References

- [OWASP Desktop Application Security Top 10: DA3 and DA10](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft: Windows Error Reporting settings](https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings)
- [Microsoft: Collecting user-mode dumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps)
- [Microsoft: WER dump types](https://learn.microsoft.com/en-us/windows/win32/api/werapi/ne-werapi-wer_dump_type)
- [Microsoft: GetTempPath2](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppath2w)
- [Microsoft .NET: Path.GetTempPath](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.gettemppath)
- [Microsoft: Clipboard operations](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-operations)
- [Microsoft: Event logging security](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)
- [Microsoft Sysinternals: Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
