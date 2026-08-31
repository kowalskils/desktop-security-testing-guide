# Filesystem and Registry Authorization Boundaries

| Field | Value |
| --- | --- |
| Test Case ID | DA5-T01 |
| Primary OWASP Category | DA5 - Improper Authorization |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test validates authorization for application files, directories, Registry keys, databases, configuration, plug-ins, update locations, exports, and per-user or machine-wide state. Unlike DA3 storage testing, the primary question is whether an unauthorized identity can perform a protected read, write, create, delete, rename, execute, ownership, or permission-change operation.

## Objective and Threat Model

Determine whether Windows ACLs and application-layer authorization enforce user, role, tenant, privilege, and integrity boundaries. Test another standard Windows user, a different application user, service identities, and a lower-integrity process where relevant. Impact includes cross-user access, configuration bypass, code replacement, persistence, and privilege escalation.

## Methodology

1. Inventory all securable paths and Registry keys created during install, first run, authentication, sensitive operations, update, repair, and uninstall.
2. Record owner, DACL, inheritance, integrity label, 32/64-bit Registry view, application role, and the process that consumes each object.
3. Build an identity/action matrix covering read, list, create, append, overwrite, rename, delete, execute, change permissions, and take ownership.
4. Verify effective access as each real test identity; do not infer results only from displayed ACL text.
5. Test parent directories and newly created children because inherited access may differ from an existing file.
6. Replace only synthetic configuration or content and observe whether the application trusts it across a boundary. Restore it immediately.
7. Test links, junctions, alternate paths, backups, updater staging, plug-in folders, and Registry virtualization when applicable.
8. Confirm application authorization still separates users who share the same Windows account or local storage.

```powershell
icacls "C:\ProgramData\Vendor\Application"
Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\Application" |
    Format-List Owner, AccessToString
```

## Evidence

Object inventory; identity/action matrix; SIDs, groups, tokens, owners, DACLs and inheritance; successful and denied operations; consuming process and privilege; controlled tamper result; cleanup; and the exact security boundary crossed.

## Pass/Fail Criteria

### Pass

Only intended identities can perform each protected operation, new objects inherit safe access, per-user/tenant data remains separated, and writable content is not trusted by a more privileged process without validation.

### Fail

Fail when an unintended identity can read protected data, modify trusted configuration or executables, create content in a privileged search/load path, change security descriptors, cross application roles, or affect another user/tenant.

### Needs Further Investigation

Use when effective identity, inherited permission, consuming process, application role, or impact of the granted access is not established.

## Remediation Guidance

- Define authorization by identity and operation before choosing storage paths.
- Apply least-privilege DACLs at creation and test inheritance for new children.
- Separate per-user and machine-wide state and never rely on UI hiding.
- Keep privileged consumers from trusting standard-user-writable content.
- Add automated ACL baselines and cross-user authorization tests.

## References

- [Microsoft: Access control lists](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
- [Microsoft: File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- [Microsoft: Registry key security](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
