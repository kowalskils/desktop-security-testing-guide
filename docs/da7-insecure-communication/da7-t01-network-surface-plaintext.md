# Network Surface and Plaintext Protocol Discovery

| Field | Value |
| --- | --- |
| Test Case ID | DA7-T01 |
| Primary OWASP Category | DA7 - Insecure Communication |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA6 - Security Misconfiguration |
| Platforms | Windows native, .NET, and Electron network clients and listeners |

## Scope and Objective

This test inventories every network path and determines whether sensitive or security-relevant data crosses an untrusted boundary without suitable confidentiality and peer authentication. It covers HTTP, WebSocket, database, file-transfer, mail, messaging, telemetry, update, discovery, DNS, custom TCP/UDP, loopback, LAN, VPN, and Internet traffic.

## Methodology

1. Capture traffic during install, first run, authentication, normal/error/offline workflows, update, telemetry, support, logout, and exit.
2. Correlate each connection with process, user, destination, resolved name, address, port, protocol, trigger, data class, credentials, and trust boundary.
3. Use Pktmon or an approved capture tool on all relevant adapters; include IPv4/IPv6, loopback, proxy/VPN, and child/helper processes.
4. Search payloads and metadata for synthetic credentials, tokens, records, documents, commands, identifiers, and update content.
5. Test DNS, redirects, alternate endpoints, fallback ports, captive/offline behavior, and service discovery for plaintext downgrade.
6. Determine whether “local” traffic crosses user/session/container boundaries or is exposed to other local processes.
7. Verify plaintext protocols are either removed, protected by an authenticated tunnel, or limited to data whose exposure and modification are explicitly acceptable.

## Evidence and Criteria

Collect connection inventory, process mapping, captures and hashes, workflow timestamps, marker matches, trust boundaries, fallback behavior, and required attacker position.

Pass when all sensitive communication uses an authenticated protected channel across its real boundary and no insecure fallback occurs. Fail for plaintext credentials/tokens/data, unauthenticated commands or updates, downgrade to plaintext, or sensitive loopback/LAN traffic accessible to unintended actors. Use `Needs Further Investigation` when payload, endpoint ownership, tunnel, process, or boundary is unknown.

## Remediation Guidance

Remove plaintext protocols; use TLS or an authenticated tunnel end to end; authenticate every peer; disable silent fallback; minimize metadata; protect local endpoints; and maintain an automated endpoint/protocol inventory.

## References

- [Microsoft: Packet Monitor](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)
- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations)
