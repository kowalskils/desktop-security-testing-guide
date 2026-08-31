# Installer, Updater, and Service Security Configuration

| Field | Value |
| --- | --- |
| Test Case ID | DA6-T01 |
| Primary OWASP Category | DA6 - Security Misconfiguration |
| Secondary Categories | DA5 - Improper Authorization; DA8 - Poor Code Quality |
| Platforms | Windows installers, updaters, services, scheduled tasks, and repair workflows |

## Scope and Objective

This test validates secure defaults and trust boundaries established by installation, update, repair, rollback, and uninstall. It covers paths, ACLs, service/task configuration, signatures, update sources, proxy behavior, staging, elevation, environment inheritance, rollback, and residual components.

## Methodology

1. Capture before/after filesystem, Registry, service, task, firewall, certificate-store, environment, and PATH state.
2. Install per-user and per-machine variants as a standard user and administrator where supported.
3. Record every elevated process, service identity, binary path, argument, working directory, recovery action, trigger, and ACL.
4. Inspect install, cache, download, staging, backup, rollback, repair, and uninstall paths for broad read/write/create/delete rights.
5. Verify packages, manifests, and metadata are authenticated before privileged use; test controlled corruption, wrong signer, expired/revoked policy, redirect, downgrade, replay, and interrupted download.
6. Verify update origin, TLS/certificate policy, proxy behavior, channel selection, and whether user-writable configuration can redirect privileged downloads or execution.
7. Test partial failure, reboot boundary, repair, rollback, and uninstall for leftover privileged services, tasks, binaries, credentials, or weakened ACLs.
8. Compare defaults with vendor hardening guidance; security must not depend on an undocumented post-install step.

## Evidence and Criteria

Collect state diffs, process/elevation tree, signatures, service/task definitions, paths and ACLs, update requests, corruption/downgrade results, rollback state, and leftovers.

Pass when secure defaults are atomic, authenticated, least-privilege, non-redirectable, downgrade-controlled, and cleanly recoverable. Fail for unsigned/unverified privileged updates, writable trusted paths, unsafe service/task configuration, attacker-controlled source/channel, insecure rollback, or residual privileged components. Use `Needs Further Investigation` when the active update policy, signer trust, effective ACL, or privileged consumer is unknown.

## Remediation Guidance

Authenticate packages and metadata before elevation; use protected absolute paths and atomic replacement; restrict sources and channels; bind rollback policy to signed version metadata; harden service/task identities and DACLs; preserve safe ACLs through repair; and test clean failure/uninstall states.

## References

- [Microsoft: Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Microsoft: SignTool](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/signtool)
- [Microsoft: Windows Installer security](https://learn.microsoft.com/en-us/windows/win32/msi/security)
