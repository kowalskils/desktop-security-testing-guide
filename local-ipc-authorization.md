# Local IPC Authentication and Authorization

| Field | Value |
| --- | --- |
| Test Case ID | DA5-T03 |
| Primary OWASP Category | DA5 - Improper Authorization |
| Secondary Categories | DA2 - Broken Authentication and Session Management; DA6 - Security Misconfiguration |
| Platforms | Named pipes, COM, RPC, local sockets, shared memory, window messages, and Electron IPC |

## Scope and Objective

This test validates authentication, authorization, isolation, message integrity, impersonation, object ownership, and replay resistance for local interprocess communication. Determine whether each server identifies the real caller and authorizes every operation and target rather than trusting channel possession, client-supplied identity, obscurity, or the UI process.

## Threat Model

Another user, session, sandboxed renderer, low-integrity process, or compromised same-user process may discover an endpoint, connect first, impersonate a server, replay messages, alter identifiers or paths, pass unexpected handles, or exploit a privileged server's failure to impersonate and reauthorize.

## Methodology

1. Inventory named pipes, COM classes, RPC endpoints, loopback ports, Unix-domain sockets, shared sections, events, mutexes, window messages, custom protocols, Electron IPC channels, and helper-process stdio.
2. Record server identity/integrity, client identities, endpoint namespace, security descriptor, remote accessibility, session scope, message schema, authentication, authorization decision, impersonation level, and privileged operations.
3. Connect as the intended user, another user/session, low-integrity process, and unauthorized renderer or helper where applicable.
4. Enumerate allowed operations without brute force; modify caller/tenant/user IDs, object paths, roles, flags, sequence numbers, and resource identifiers one field at a time.
5. Replay valid synthetic requests after logout, account switch, process restart, and server restart.
6. Attempt server pre-creation or endpoint substitution only with benign lab endpoints; verify clients authenticate the intended server.
7. For named pipes, inspect the DACL, reject unintended remote clients, constrain instances, verify client identity, use the correct impersonation level, check impersonation return values, and always revert safely.
8. For privileged servers, confirm file/Registry/network actions occur under the authorized client or an explicit policy decision, not automatically under server privilege.
9. For Electron, verify renderer-to-main messages use fixed channel allowlists, validate sender/frame/origin where meaningful, validate schemas and paths, and never expose a generic privileged method bridge.
10. Test malformed length, type, ordering, duplicate, cancellation, disconnect, and concurrent requests for authorization-state confusion without denial-of-service payloads.

## Evidence

Endpoint inventory; server/client tokens and sessions; security descriptors; message schemas; allowed/denied identity-operation matrix; impersonation behavior; modified/replayed request results; server-authentication result; Electron sender context; and exact privileged side effect.

## Pass/Fail Criteria

### Pass

Endpoints restrict connection appropriately, clients authenticate servers where required, servers derive trustworthy caller identity, authorize every operation and object, constrain impersonation and delegation, validate messages, and reject replay or cross-session misuse.

### Fail

Fail when an unintended client connects to a sensitive endpoint, client-supplied identity is trusted, object-level authorization is missing, a privileged server acts without successful impersonation/authorization, another user/session replays requests, a fake server captures secrets, or a renderer gains generic privileged access.

### Needs Further Investigation

Use when endpoint ownership, DACL, caller token, session, impersonation level, remote reachability, message purpose, or resulting privilege cannot be established.

## Remediation Guidance

- Apply explicit least-privilege endpoint security descriptors and per-session/logon isolation where required.
- Authenticate both caller and server; derive identity from the OS channel rather than message fields.
- Authorize every verb and object inside the server and bind requests to current session state.
- Check impersonation results, minimize delegation, revert reliably, validate schemas, bound resources, and add anti-replay state.
- Expose narrow Electron IPC methods with sender validation instead of generic filesystem, shell, Registry, or network bridges.

## References

- [Microsoft: Named pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [Microsoft: Client/server access control overview](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-server-access-control)
- [Electron: Security](https://www.electronjs.org/docs/latest/tutorial/security)
