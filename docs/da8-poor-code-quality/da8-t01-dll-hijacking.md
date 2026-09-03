# DLL Hijacking and Unsafe Dependency Loading

| Field | Value |
| --- | --- |
| Test Case ID | DA8-T01 |
| Primary OWASP Category | DA8 - Poor Code Quality |
| Secondary Categories | DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test covers native DLL resolution during startup, delayed feature activation, plug-in discovery, updates, and privileged helper execution. Include native libraries used by .NET P/Invoke, mixed-mode code, and Electron native modules. Managed assembly and JavaScript module resolution require separate runtime-specific analysis; do not assume they follow the Windows DLL search order.

## Objective and Threat Model

Determine whether an attacker can influence the library selected by a real workflow across an intended trust boundary. Include direct and transitive dependencies. A missing-file event, unsigned library, or relative library name alone is not a confirmed vulnerability.

Record attacker identity, writable locations, launch influence, victim identity, integrity level, and required interaction. Consider a different local user, a standard user influencing a privileged helper, and content opened from an untrusted directory.

A per-user installation is not automatically vulnerable because its owner can modify its files. Explain the additional authority or protected behavior exposed. Do not label same-user execution as privilege escalation without evidence of a higher-privilege consumer.

## Prerequisites and Safety

- Obtain authorization for the exact application, accounts, workflows, and directories.
- Use a restorable Windows lab with synthetic data. Record OS build, packaging, runtime, architecture, application version, and artifact SHA-256 hashes.
- Keep monitoring privileges separate from attacker privileges. An elevated capture tool must not silently elevate the application.
- Do not modify system DLLs, global search settings, production services, or unrelated files.
- Use only an approved benign test DLL if substitution is needed. No shells, persistence, network activity, or privileged actions are necessary.

## Tools

- Process Monitor: correlate file lookups, image loads, and process creation.
- Process Explorer: inspect identity and the lower-pane DLL view. This is a snapshot, not a history of unloaded modules.
- PowerShell and `icacls`: record hashes, signatures, identities, and permissions.
- PE import inspection and an approved debugger: investigate imports, delayed loads, call arguments, and stacks. Static dependency output cannot enumerate all runtime loads.

Signature inspection does not prove signature or publisher enforcement before loading. See [DA8-T02](da8-t02-binary-hardening-code-signing.md) for release-integrity testing.

## Testing Methodology

### Step 1 - Establish the Baseline

1. Inventory executables, services, helpers, plug-ins, and native modules in the workflow.
2. Record launch command, parent process, working directory, process environment, identity, integrity level, and architecture. Include supported shortcut, file association, updater, and service launches.
3. Start capture before launching a fresh process. Exercise startup and one feature at a time, marking timestamps.
4. Inspect module paths in Process Explorer's lower-pane DLL view. Identify the actual consumer, not just the visible window.
5. Repeat for supported architectures and installation modes; do not extrapolate one configuration to every release.

Example read-only baseline commands; replace the example path:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Program Files\ExampleApp\ExampleApp.exe'
Get-AuthenticodeSignature -LiteralPath 'C:\Program Files\ExampleApp\ExampleApp.exe'
whoami /all
```

`whoami` describes its shell, not a separate application or service. Collect victim identity independently.

### Step 2 - Separate Lookups from Loads

1. Enable filesystem and process/thread activity in Process Monitor. Identify the target and children through the process tree; record PIDs and creation times.
2. Retain the underlying capture without enabling Drop Filtered Events. Use separate display views:
   - File operations such as `CreateFile` and `QueryOpen` for candidate paths, including `NAME NOT FOUND`, `PATH NOT FOUND`, `ACCESS DENIED`, and successful results.
   - `Load Image` events for resulting mapped module paths.
3. Correlate names, timestamps, process/thread identity, and available stacks. An unrelated file probe is not necessarily a loader request.
4. Record the observed lookup sequence and final load, if any. A `Load Image`-only filter does not reveal missing-file probes.
5. Save the native capture and focused exports. Document gaps and processes that exited before inspection.

Optional-library probes may be normal. A successful file open does not prove executable loading. Investigate execution versus resource-only mapping before claiming code execution.

### Step 3 - Validate Attacker Influence

1. Identify the exact directory or configuration value the attacker can influence and when that influence is available.
2. Inspect the candidate file, containing directory, and relevant parents:

```powershell
icacls 'C:\Path\To\CandidateDirectory'
icacls 'C:\Path\To\CandidateDirectory\Candidate.dll'
```

3. Evaluate effective access: group membership, inherited denies, file creation, replacement, and directory deletion/recreation. ACL output alone is not an effective-access verdict.
4. Where authorized, verify the required operation using a uniquely named harmless scratch file under the attacker account. Remove only that artifact afterward. Creation permission does not establish permission to replace an existing DLL.
5. Record actual resolution behavior. Packaging, manifests, API sets, already-loaded modules, and Known DLLs can affect selection.
6. Treat installation, temporary, and system directory names as context, not proof of trust. Confirm who can modify the exact path.

Cross-reference [DA5-T01](../da5-improper-authorization/da5-t01-filesystem-registry.md) for permission boundaries.

### Step 4 - Review Loading Controls

Use source, configuration, disassembly, or debugger observations where available. Process Monitor shows resolved paths, not whether the caller supplied an absolute path.

- Review transitive dependencies: an absolute path for the first DLL does not secure its dependencies by itself.
- Verify loader arguments, initialization timing, return-value checks, and fallback behavior.
- Review `SetDefaultDllDirectories` and per-call `LoadLibraryEx` restrictions. Initialization cannot retroactively protect imports loaded before it runs.
- For a validated full path, assess whether `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` combined with `LOAD_LIBRARY_SEARCH_SYSTEM32` fits the dependency layout. Protect the DLL directory; flags do not make writable directories trustworthy.
- With `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`, inspect application and explicitly added directories too.
- Validate `AddDllDirectory` inputs and lifetime. Do not rely on ordering among multiple added directories.
- `SafeDllSearchMode` moves the working directory later in the standard search order; it does not exclude it.
- Inspect `SetDllDirectory` arguments: a nonempty directory changes search behavior and effectively disables safe search mode while included; an empty string removes the working directory; NULL restores default behavior.
- For .NET, inspect native imports and custom native-library resolvers. For Electron, follow native add-on loads into the responsible process and validate their dependencies.

### Step 5 - Confirm One Candidate Safely

1. Select a repeatable trigger with demonstrated attacker influence. Record baseline module paths and behavior.
2. In the isolated lab, place an approved benign DLL under the attacker account in the exact candidate location. Match architecture and the necessary import/export contract; an invalid image or missing export is not proof of execution.
3. Record its hash and location. Do not overwrite an existing library without explicit approval and verified restoration.
4. Restart the consumer to avoid reusing an already-loaded module. Repeat the original sequence without granting the attacker additional rights.
5. Capture module path and process context. If claiming execution, obtain debugger or approved benign marker evidence of initialization or an expected function call; image mapping alone is insufficient.
6. Distinguish resource mapping, rejected images, crashes, and policy blocks from executable loading. One rejected DLL does not prove that all unauthorized DLLs would be rejected.
7. Remove the exact test artifact, restore approved changes, restart, and repeat the baseline. Preserve cleanup evidence.

If substitution cannot be performed safely, report the supported observation and uncertainty rather than claiming a confirmed exploit.

### Step 6 - Retest the Fix

Repeat the original trigger with the same candidate and account. Confirm the legitimate dependency still loads, the unauthorized candidate is excluded or rejected before execution, and no fallback recreates the issue. Retest delayed features, supported launch methods, privileged consumers, and affected architectures.

## Evidence to Collect

- Build, OS, runtime, packaging, architecture, hashes, and tool versions.
- Attacker capabilities, victim identity/integrity, launch details, working directory, and relevant environment.
- Timestamped lookups and loads, actual paths, stacks, capture limitations, and reproduction steps.
- Effective-access evidence for creation or replacement, including the account used.
- Loader arguments/configuration and direct-versus-transitive dependency analysis where available.
- Baseline, controlled test, cleanup, and remediation-retest results; test DLL hash and execution evidence if claimed.
- Explicit separation of observed conditions, demonstrated impact, and untested assumptions.

## Pass/Fail Criteria

### Pass

For the recorded workflows and threat model, unauthorized locations cannot supply executable dependencies, loading controls work before relevant loads, and negative tests preserve legitimate operation. State limitations; this is not proof that every possible load is secure.

### Fail

Fail when reproducible evidence shows an attacker can cause an unauthorized executable dependency to load across the defined trust boundary. Explain trigger, consumer, privileges, and impact. Report a separately proven permission weakness under DA5 or DA6 even if DLL execution remains unconfirmed.

### Needs Further Investigation

Use for missing-file probes, ambiguous permissions, unresolved call behavior, resource mapping, or unconfirmed triggers. Specify the additional evidence needed.

## Expected Findings

- A privileged helper resolves a dependency from standard-user-writable staging.
- Opening untrusted content changes resolution and selects an unintended native library.
- A protected top-level DLL loads a transitive dependency from an attacker-controlled location.
- An optional missing library produces probes but no confirmed unsafe load: an investigation lead, not a confirmed hijack.
- A per-user plug-in directory behaves as designed, with no demonstrated crossing of the defined trust boundary.

## Remediation Guidance

- Use validated paths and narrowly scoped supported search controls for direct and transitive dependencies.
- Protect executable dependency directories against the relevant attacker, especially for elevated helpers and services.
- Remove unnecessary search locations and obsolete requests; avoid unsafe fallback.
- Keep user-extensible plug-ins outside privileged execution paths unless an explicit, enforced trust policy permits them.
- Verify required integrity and publisher policy before execution; signing alone does not enforce that policy.
- Preserve regression tests for the original path, account, workflow, and architectures.

## References

- [OWASP Desktop Application Security Top 10](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft: Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [Microsoft: Dynamic-link library security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security)
- [Microsoft: LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [Microsoft: SetDefaultDllDirectories](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories)
- [Microsoft: SetDllDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectoryw)
- [Microsoft Sysinternals: Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Microsoft Sysinternals: Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
