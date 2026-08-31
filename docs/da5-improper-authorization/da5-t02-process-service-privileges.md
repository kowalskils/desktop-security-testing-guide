# Process, Service, UAC, and Privileged Operation Boundaries

| Field | Value |
| --- | --- |
| Test Case ID | DA5-T02 |
| Primary OWASP Category | DA5 - Improper Authorization |
| Secondary Categories | DA6 - Security Misconfiguration; DA8 - Poor Code Quality |
| Platforms | Windows processes, services, scheduled tasks, installers, and updaters |

## Scope and Objective

This test validates process tokens, integrity levels, UAC manifests, service identities and permissions, privileged helpers, scheduled tasks, installers, updaters, and administrative operations. Determine whether elevation is necessary, explicit, narrowly scoped, bound to the requesting identity, and resistant to unprivileged input or executable replacement.

## Threat Model

A standard user may start or influence a privileged process, modify its configuration or inputs, control its working directory/environment, replace a binary, invoke undocumented operations, race validation and use, or replay a privileged request. Impact includes elevation, security-control bypass, persistence, and cross-user actions.

## Methodology

1. Map every process, service, task, helper, updater, and installer with user SID, groups, privileges, integrity level, executable, command line, parent, session, and trigger.
2. Inspect embedded manifests for `asInvoker`, `highestAvailable`, `requireAdministrator`, and `uiAccess`; verify observed elevation and secure-desktop consent.
3. Run normal workflows as a standard user and identify operations that elevate unnecessarily or fail to separate privileged work.
4. Inspect service account, service DACL, binary path, arguments, recovery actions, start type, dependencies, and executable/directory ACLs.
5. Test whether a standard user can change configuration, start/stop/control, replace binaries, alter arguments, or influence DLLs, scripts, plug-ins, updates, temp paths, environment, or working directory.
6. Send controlled requests to privileged helpers as another user/session and with modified object identifiers, paths, roles, and replayed request data.
7. Verify the privileged component reauthorizes the caller and target operation after elevation rather than trusting the unelevated UI.
8. Test cancellation, rollback, update, repair, uninstall, and time-of-check/time-of-use windows using benign artifacts.

## Evidence

Process/token matrix; manifests; UAC prompts; service/task configuration and DACLs; path ACLs; allowed/denied controls; privileged request and caller identity; tamper/replay results; race prerequisites; and cleanup.

## Pass/Fail Criteria

### Pass

Components run with minimum privileges, privileged operations require explicit authorized elevation, services and helpers independently authorize callers and targets, and unprivileged identities cannot modify or redirect privileged execution.

### Fail

Fail for unnecessary permanent elevation, writable privileged binaries/configuration, dangerous service rights, unquoted or attacker-influenceable execution, caller-confused helpers, authorization performed only in the UI, cross-session request acceptance, or replay/race causing an unauthorized privileged operation.

### Needs Further Investigation

Use when the token, service right, privileged request contract, consuming path, caller identity, trigger, or resulting operation cannot be established.

## Remediation Guidance

- Run the UI `asInvoker` and isolate minimal privileged operations in a narrow broker.
- Reauthorize caller, role, target, and parameters inside the privileged component.
- Use least-privilege service identities and DACLs; protect every executable and configuration path.
- Use absolute quoted paths, validated handles, safe temporary objects, anti-replay state, and atomic operations.
- Remove unnecessary privileges and test standard-user workflows continuously.

## References

- [Microsoft: How User Account Control works](https://learn.microsoft.com/en-us/windows-server/security/user-account-control/how-user-account-control-works)
- [Microsoft: Application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests)
- [Microsoft: Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
