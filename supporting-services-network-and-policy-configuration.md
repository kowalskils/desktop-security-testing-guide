# Supporting Services, Network Listeners, Firewall, and System Policy Configuration

| Field | Value |
| --- | --- |
| Test Case ID | DA6-T03 |
| Primary OWASP Category | DA6 - Security Misconfiguration |
| Secondary Categories | DA2 - Broken Authentication; DA5 - Improper Authorization; DA7 - Insecure Communication |
| Platforms | Windows services, local databases, listeners, firewall, Group Policy, Registry policy, and third-party services |

## Scope and Objective

This test validates the secure configuration of supporting components installed, enabled, or consumed by a desktop application. It covers service accounts, listeners, bind addresses, ports, authentication, default credentials, remote administration, firewall rules, discovery, databases, message brokers, web interfaces, Group Policy, Registry policy, certificate trust, and third-party defaults.

## Methodology

1. Inventory processes, services, drivers, listeners, ports, protocols, bind addresses, firewall rules, databases, brokers, web consoles, remote-management features, and policy keys.
2. Map every component to owner, version, account, privilege, configuration source, authentication, authorization, encryption, network exposure, update mechanism, and business requirement.
3. Compare a clean default installation with vendor hardening guidance and enterprise policy.
4. Test whether listeners bind only to required interfaces and whether IPv4, IPv6, loopback, LAN, VPN, and public profiles behave consistently.
5. Verify firewall rules are narrowly scoped by program, service, protocol, port, direction, profile, interface, and remote address; remove/disable the application and check for stale rules.
6. Test synthetic default, blank, weak, shared, and undocumented credentials only on authorized lab components; verify first-use change and lockout policy.
7. Verify remote administration, discovery, debug consoles, metrics, health endpoints, and database consoles are disabled or protected by default.
8. Modify controlled Group Policy and Registry policy values as authorized users and confirm precedence, fail-closed behavior, tamper protection, refresh, and rollback.
9. Test supporting-service failure, unavailable policy, invalid certificate, network-profile change, and partial upgrade for insecure fallback.
10. Confirm third-party services are patched, minimally configured, and removed when no longer required.

## Evidence and Criteria

Collect component/listener inventory, bind and firewall state, service identities, authentication results, policy paths and precedence, default-versus-hardened diffs, failure behavior, versions, and residual configuration.

Pass when only required components and listeners are enabled, exposure is least-privilege and least-network, authentication and encryption are enforced, firewall/policy defaults are narrow, and failures do not weaken controls. Fail for unnecessary public listeners, broad firewall rules, default credentials, exposed administration/debug interfaces, user-writable security policy, insecure fallback, stale rules, or unsupported third-party defaults. Use `Needs Further Investigation` when ownership, exposure, policy source, authentication path, or active consumer is unclear.

## Remediation Guidance

Disable unnecessary components; bind locally where possible; scope firewall rules precisely; require unique credentials and secure first use; protect policy sources and define precedence; fail closed; remove stale rules and services; patch dependencies; and continuously compare deployed configuration with an approved baseline.

## References

- [Microsoft: Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)
- [Microsoft: Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
- [Microsoft: Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
