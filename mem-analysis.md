# Sensitive Data Exposure in Process Memory

| Field | Value |
| --- | --- |
| Test Case ID | DA3-T01 |
| Primary OWASP Category | DA3 - Sensitive Data Exposure |
| Secondary Categories | DA2 - Broken Authentication and Session Management; DA4 - Improper Cryptography Usage |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test determines whether a Windows desktop application retains sensitive data in process memory longer than required for an authorized operation. It evaluates exposure during data entry and use, after a sensitive view is closed, after logout or session timeout, and after an application-level clear or account-switch operation.

Examples of in-scope data include:

- Passwords, PINs, recovery codes, and one-time authentication values
- Session tokens, refresh tokens, API keys, and client secrets
- Cryptographic keys, key material, and decrypted protected content
- Personally identifiable, financial, healthcare, or regulated data
- Connection strings and service credentials
- Sensitive clipboard, form, document, search, and message content processed by the application

The presence of sensitive data while it is actively required does not automatically constitute a vulnerability. The test focuses on unnecessary copies, excessive retention, exposure after a security boundary transition, and data that remains recoverable beyond its intended lifetime.

## Objective

The objectives of this test are to determine whether:

- Sensitive values appear in process memory in plaintext or another directly reusable form.
- The application creates more in-memory copies than the workflow reasonably requires.
- Sensitive data remains recoverable after the relevant view, document, or operation is closed.
- Credentials and session material remain recoverable after logout, account switch, revocation, or session timeout.
- Memory handling is consistent across native, managed, and embedded browser components.
- A lower-privileged user or unauthorized process can obtain a dump of the target process.
- Application and operating-system controls reduce the likelihood and impact of memory disclosure.

## Threat Model

The test considers attackers who have obtained local code execution, access to a diagnostic or crash dump, access to a shared workstation, or the ability to inspect the process through debugging or support tooling. It also considers accidental disclosure through crash collection, support bundles, endpoint-management systems, or insecurely stored dump files.

Potential impacts include account takeover, session replay, unauthorized decryption, disclosure of regulated data, access to remote services, and cross-user data exposure.

This test does not assume that an application can completely prevent a sufficiently privileged administrator or kernel-level attacker from reading process memory. Findings should distinguish avoidable application retention from exposure that depends on an already dominant operating-system privilege.

## Prerequisites and Safety

- Obtain written authorization to capture and analyze process memory.
- Use an isolated Windows test environment with a restorable snapshot.
- Use synthetic accounts and synthetic data. Do not enter real passwords, production tokens, personal data, or customer records.
- Create unique marker values for each data type and test state so that matches can be attributed accurately.
- Record the application version, architecture, installation source, executable hash, Windows version, and test-account privilege level.
- Protect dump files as highly sensitive artifacts. Store them in an access-controlled test directory and do not upload them to public analysis services.
- Confirm the approved retention and deletion procedure before capture. Memory dumps may contain unrelated secrets from the test session.
- Close unrelated applications and remove unnecessary secrets from the test environment before testing.

## Test Data Design

Use distinctive, non-production marker values that are unlikely to occur naturally. Do not reuse the same marker for different fields or states.

Example marker scheme:

| Data Type | Example Pattern |
| --- | --- |
| Password | `DSTG-PWD-A7F4-NotARealPassword!` |
| Access token | `DSTG-ACCESS-19C2-SYNTHETIC` |
| Refresh token | `DSTG-REFRESH-83D1-SYNTHETIC` |
| Personal record | `DSTG-PII-USER-5E90` |
| Document content | `DSTG-DOC-4B27-SYNTHETIC-CONTENT` |

Record the exact workflow and state associated with each marker. Where possible, test a unique value in each repetition so that a match cannot be attributed to a previous run.

## Tools

Select tools according to the application technology and assessment constraints:

1. **ProcDump**
   - Captures user-mode process dumps from the command line.
   - A full dump is normally required when searching broadly for application data in committed process memory.

2. **Windows Task Manager**
   - Can create a user-mode dump through the process context menu.
   - Useful for controlled manual testing when command-line tooling is unavailable.

3. **WinDbg**
   - Opens and analyzes user-mode dump files and supports inspection of memory regions, threads, modules, and managed or native state.

4. **Sysinternals Strings**
   - Extracts printable ANSI and Unicode strings from a dump for initial triage.
   - String extraction is not sufficient to establish object lifetime, ownership, or exploitability.

5. **Process Explorer, VMMap, and PowerShell**
   - Record process identity, integrity level, loaded modules, architecture, memory layout, and executable metadata.

6. **Technology-specific debugging extensions**
   - May help attribute data to .NET objects, native allocations, Chromium/Electron processes, or third-party libraries when deeper analysis is authorized.

Tool output is evidence, not a final finding. A valid conclusion requires a controlled marker, a defined application state, and a reproducible match.

## Testing Methodology

### Step 1 - Establish the Process and Security Baseline

1. Record the executable path, file hash, signer, architecture, and application version.
2. Identify the process tree created by the application.
3. Record the user identity, integrity level, enabled privileges, and whether the target runs as a desktop process or service.
4. For multi-process applications, identify which process handles authentication, documents, rendering, networking, and background operations.
5. Determine who can open the process or create a dump under the tested Windows configuration.
6. Record any endpoint-security, anti-malware, anti-debugging, or protected-process controls that affect capture.

Do not weaken operating-system protections merely to obtain a dump unless bypassing that control is explicitly in scope. If capture requires administrative or debugging privileges, record that prerequisite as part of the risk assessment.

### Step 2 - Define the State Matrix

Capture and compare memory at security-relevant states:

| State | Purpose |
| --- | --- |
| S0 - Baseline | Application started before synthetic sensitive data is entered |
| S1 - Input | Sensitive marker entered but not submitted |
| S2 - Active use | Authentication or sensitive operation completed and data is in use |
| S3 - View closed | Sensitive page, document, dialog, or workflow closed |
| S4 - Logout | Application logout or account switch completed |
| S5 - Timeout | Session expired through the application's inactivity mechanism |
| S6 - Clear/revoke | Application clear, cache reset, token revocation, or equivalent control completed |

Not every application supports every state. Record omitted states and the reason. Restart the application between independent scenarios when necessary to prevent one workflow from contaminating another.

### Step 3 - Capture the Baseline Dump

1. Launch the application normally and allow initialization to complete.
2. Do not enter any marker value.
3. Record the target process IDs and capture time.
4. Capture a full dump for each in-scope process.

Example using ProcDump from an elevated test console when required:

```powershell
New-Item -ItemType Directory -Path "C:\DSTG\Dumps" -Force | Out-Null
procdump.exe -accepteula -ma <PID> "C:\DSTG\Dumps\S0-baseline.dmp"
```

Use the numeric PID recorded for the specific process. For an Electron or brokered application, capture the relevant child processes as well as the parent and preserve the process-role mapping.

### Step 4 - Exercise the Sensitive Workflow

1. Enter the unique synthetic marker for the selected field or data type.
2. Capture S1 while the value is present in the input control, when applicable.
3. Submit the operation and capture S2 while the sensitive data is legitimately in use.
4. Record timestamps and the exact user action immediately preceding each capture.
5. Repeat with separate markers for credentials, tokens, records, and documents rather than placing unrelated values into one scenario.

Avoid interpreting S1 or S2 plaintext presence in isolation. Some values must temporarily exist in usable form. The primary questions are how many copies exist, where they are held, who can dump the process, and whether the values persist after use.

### Step 5 - Exercise Cleanup and Session Boundaries

1. Close the sensitive view or document and capture S3.
2. Log out or switch accounts using the application's supported workflow and capture S4 without terminating the process.
3. In a separate run, allow the session to expire naturally and capture S5.
4. If the application exposes a clear-cache, lock, revoke, or reset function, use it and capture S6.
5. Where supported, authenticate as a second synthetic user after logout and verify whether the first user's markers remain recoverable.
6. Record whether background, renderer, helper, crash-handler, or service processes survive the transition.

Closing the main window is not equivalent to clearing memory if application or helper processes remain running.

### Step 6 - Search for Controlled Markers

Perform both ANSI and Unicode-aware searches. An initial triage can use Sysinternals Strings:

```powershell
strings.exe -n 6 -o "C:\DSTG\Dumps\S4-logout.dmp" |
    Select-String -SimpleMatch "DSTG-PWD-A7F4-NotARealPassword!"

strings.exe -u -n 6 -o "C:\DSTG\Dumps\S4-logout.dmp" |
    Select-String -SimpleMatch "DSTG-PWD-A7F4-NotARealPassword!"
```

Repeat the search for every marker and every state. Record:

- Whether the full marker is present
- The number of observable matches
- The dump and process containing each match
- The string encoding and file offset reported by the tool
- Whether the value is directly reusable or only a non-sensitive fragment

Do not include real secret values in report screenshots or filenames.

### Step 7 - Validate and Attribute Matches

1. Open relevant dumps in WinDbg or another approved debugger.
2. Confirm that the match belongs to committed process memory rather than dump metadata, a filename, tester annotation, or tool command line.
3. Determine whether the match is associated with:
   - A native heap or stack allocation
   - A managed string, array, or object
   - A UI control or clipboard-related object
   - An Electron renderer, browser, utility, or crash-handler process
   - A third-party SDK, authentication library, database driver, or telemetry component
4. Determine whether multiple copies exist and whether a copy remains reachable by the application.
5. Repeat the workflow with a new marker to demonstrate reproducibility.

A match in a dump proves that the bytes were present at capture time. It does not, by itself, prove that an unprivileged attacker can obtain the dump or that the value remains valid and reusable.

### Step 8 - Validate Token and Key Reusability Safely

When explicitly authorized, determine whether a recovered synthetic token, session identifier, or key remains usable after logout, timeout, or revocation.

- Use only the controlled test account and approved test environment.
- Prefer a harmless authenticated read operation over any state-changing action.
- Record the server-side session state and expiration time.
- Stop after establishing whether the value is accepted or rejected.

Do not replay production credentials or tokens. If replay validation is out of scope, report memory presence and apparent validity separately without claiming account takeover.

### Step 9 - Compare Results Across States

Create a result matrix for every marker:

| Marker | S0 | S1 | S2 | S3 | S4 | S5 | S6 | Reusable After Boundary |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Example credential marker | No | Yes | Yes | No | No | No | No | No |

Compare copies and processes across states. Give particular attention to values that:

- First appear only after a sensitive operation
- Persist after logout, timeout, account switch, or revocation
- Remain in a long-lived helper or renderer process
- Belong to a previous user after a new user signs in
- Can still authenticate, decrypt, or authorize an operation

### Step 10 - Protect and Dispose of Evidence

1. Store dumps and extracted strings only in the approved evidence location.
2. Restrict access to the assigned assessment team.
3. Redact sensitive values from the final report while preserving enough of each synthetic marker to correlate evidence.
4. Record dump hashes if evidence integrity must be demonstrated.
5. At the end of the approved retention period, delete dumps and intermediate string exports using the organization's evidence-disposal procedure.

## Technology-Specific Considerations

### Native Win32

- Review stack, heap, static, and unmanaged buffer lifetimes.
- Check whether buffers are cleared before release when they contain high-value secrets.
- Look for duplicated conversions between ANSI, Unicode, and binary representations.
- Consider third-party controls and libraries that may retain their own copies.

### .NET

- Immutable `System.String` values cannot be cleared in place and may survive until garbage collection; minimize creating strings for secrets.
- Garbage collection is not a security-boundary transition and does not guarantee immediate removal of sensitive bytes.
- `SecureString` does not eliminate plaintext exposure when the value must be used and is not recommended as a universal solution for new .NET development.
- Prefer short-lived buffers where supported, avoid unnecessary conversions and logging, and use opaque handles to externally protected credentials when the architecture permits it.

### Electron

- Map markers across the main process, renderer processes, utility processes, and crash handlers.
- Review form-state retention, renderer caches, preload scripts, IPC messages, developer tooling, and crash reporting.
- Confirm that logout clears sensitive state from every relevant process, not only the visible renderer.
- Account for Chromium process reuse: closing a window may not terminate the process that handled the secret.

## Evidence to Collect

- Application, executable, and operating-system version information
- Executable hashes, signer information, architecture, and process tree
- Test-user privilege level and process integrity level
- Unique marker inventory mapped to workflows and application states
- Capture timestamps, process IDs, dump filenames, and SHA-256 hashes
- Search commands, string encoding, offsets, match counts, and debugger attribution
- The state comparison matrix for every tested marker
- Evidence showing whether a recovered synthetic token or key remained reusable
- Required privileges and controls affecting the ability to capture process memory
- Cleanup and evidence-disposal record

## Pass/Fail Criteria

### Pass

The test passes when high-value sensitive data is limited to the shortest practical lifetime, unnecessary copies are not observed, and controlled markers are no longer recoverable in a directly usable form after their defined security boundary, such as logout, timeout, account switch, view closure, clear, or revocation. Process access and dump files must also be protected according to the application's threat model.

### Fail

The test fails when a controlled sensitive value remains recoverable beyond its required lifetime and the retained value creates a credible confidentiality or authentication risk. Examples include:

- A password, PIN, recovery code, or equivalent credential remains in plaintext after submission or logout without a justified operational need.
- A valid session or refresh token remains recoverable and reusable after logout, timeout, revocation, or account switch.
- Decrypted protected content or key material remains recoverable after the user closes or locks the relevant resource.
- One user's sensitive data remains accessible after another user begins a session in the same long-lived process.
- A standard user can capture a higher-privileged application's memory and recover sensitive data across a meaningful security boundary.
- Sensitive dumps are written to a location accessible to unauthorized users or included in support artifacts without appropriate protection.

Severity should reflect the data type, validity, reusability, retention period, privileges required to capture memory, affected users, and security boundary crossed.

### Needs Further Investigation

Use this outcome when a fragment or encoded value is present but its sensitivity, ownership, lifetime, validity, or attacker accessibility cannot be established. Also use it when capture was possible only after intentionally disabling an in-scope security control.

## Expected Findings

### Secure or Expected Conditions

- Synthetic credentials are absent after submission or the earliest practical cleanup point.
- Session and key material is absent or unusable after logout, timeout, account switch, or revocation.
- Sensitive document and record content is released after the relevant workflow closes.
- Long-lived helper and renderer processes do not retain previous-user data.
- Process access and diagnostic artifacts are restricted to authorized identities.
- Crash and support workflows treat dumps as sensitive data.

### Potential Findings

- Plaintext credentials persist in UI controls, managed strings, native buffers, or third-party libraries.
- Tokens remain in a renderer, networking component, or authentication SDK after logout.
- The application clears its visible state but a helper process retains the same values.
- Multiple unnecessary copies of secrets remain across encodings or processes.
- Sensitive values from one account remain after a second account signs in.
- Full dumps are stored in a user-accessible temporary directory or attached to support packages without encryption and access control.
- Process permissions allow an unintended lower-privileged identity to obtain a dump.

## Remediation Guidance

- Minimize the time and number of locations in which sensitive data exists in directly usable form.
- Avoid immutable general-purpose strings for secrets when a short-lived, clearable buffer or opaque credential handle is available.
- Clear mutable buffers in a way that the compiler or runtime will not optimize away, using platform-supported primitives where applicable.
- Remove references and application-level caches promptly, while recognizing that garbage collection alone does not guarantee immediate byte removal.
- Invalidate tokens and server-side sessions during logout, account switch, password change, and revocation.
- Clear every process and component that receives sensitive state, including renderers, helpers, plug-ins, authentication libraries, and crash handlers.
- Avoid placing credentials, tokens, keys, or sensitive records in command lines, environment variables, logs, exception messages, telemetry, or crash annotations.
- Restrict process access, debugging privileges, dump locations, support bundles, and crash-upload destinations according to the threat model.
- Use short-lived credentials and least-privilege scopes to reduce the impact of unavoidable transient exposure.
- Add automated tests that verify session invalidation and application-state cleanup at each security boundary.

## References

- [OWASP Desktop Application Security Top 10: DA3 - Sensitive Data Exposure](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft Sysinternals: ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)
- [Microsoft Sysinternals: Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
- [Microsoft: Create a memory dump for a user-mode process with Task Manager](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/task-manager-live-dump#create-a-memory-dump-for-a-user-mode-process)
- [Microsoft: Analyze a user-mode dump file with WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/analyzing-a-user-mode-dump-file)
- [Microsoft .NET: SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring)
