# File Handler, URI Scheme, Shell, and Parser Configuration

| Field | Value |
| --- | --- |
| Test Case ID | DA6-T02 |
| Primary OWASP Category | DA6 - Security Misconfiguration |
| Secondary Categories | DA1 - Injections; DA5 - Improper Authorization; DA8 - Poor Code Quality |
| Platforms | Windows file associations, custom URI schemes, shell verbs, previews, imports, and parsers |

## Scope and Objective

This test validates externally reachable activation and parsing surfaces registered by a desktop application. It covers file associations, shell verbs, command templates, custom protocols, drag/drop, import/export, previews, thumbnails, print handlers, document links, archives, and content-type decisions.

## Methodology

1. Inventory registered extensions, ProgIDs, URL protocols, shell commands, COM handlers, preview/thumbnail providers, auto-start activation, and application manifests.
2. Record the exact command template, quoting, executable path, working directory, integrity level, caller, and whether untrusted content can trigger it remotely or from a browser/email client.
3. Test benign paths containing spaces, quotes, shell metacharacters, UNC/device paths, alternate streams, long paths, Unicode, environment strings, and relative segments.
4. Test extension/content mismatches, polyglots, empty/truncated/oversized files, nested archives, traversal names, links, external references, and parser feature flags without destructive payloads.
5. Verify validation is based on trusted content and structure rather than extension or user-controlled MIME alone.
6. Confirm URI parameters are parsed structurally, length-bounded, allowlisted, and never concatenated into shell, PowerShell, SQL, template, or browser execution.
7. Test activation while logged out, under another application role, from another Windows user/session, and when the target operation requires elevation.
8. Verify handlers run at minimum privilege and do not cause unexpected network access, credential forwarding, unsafe temporary extraction, or automatic active-content execution.

## Evidence and Criteria

Collect registrations, command templates, activation/process traces, input corpus and hashes, parser results, authorization state, temp/network effects, crashes, and cleanup.

Pass when registrations use protected quoted paths, parsers validate structure and bound resources, active features are disabled by default, and activation reauthorizes sensitive operations. Fail for command/argument injection, extension-only trust, traversal or unsafe extraction, unauthenticated privileged activation, dangerous external references, or insecure parser defaults. Use `Needs Further Investigation` when handler reachability, parser ownership, active feature, or resulting operation is unclear.

## Remediation Guidance

Use structured argument and URI APIs; quote and protect executable paths; allowlist schemes/actions; validate content before processing; sandbox complex parsers; disable external entities, scripts, macros, and network retrieval by default; extract to private directories; bound nesting and size; and reauthorize after activation.

## References

- [Microsoft: File types and file associations](https://learn.microsoft.com/en-us/windows/win32/shell/fa-file-types)
- [Microsoft: Application registration](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration)
- [Microsoft: Launching applications with ShellExecute](https://learn.microsoft.com/en-us/windows/win32/shell/launch)
