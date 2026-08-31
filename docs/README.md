# Desktop Security Testing Guide Index

This directory organizes executable security test cases by their primary OWASP Desktop Application Security Top 10 category.

## DA1 - Injections

Planned.

## DA2 - Broken Authentication and Session Management

Planned.

## DA3 - Sensitive Data Exposure

- [DA3-T01 - Sensitive Data Exposure in Process Memory](da3-sensitive-data-exposure/da3-t01-process-memory.md)
- [DA3-T02 - Sensitive Data in Binaries and Application Resources](da3-sensitive-data-exposure/da3-t02-binaries-resources.md)
- [DA3-T03 - Sensitive Data in Local Storage and the Windows Registry](da3-sensitive-data-exposure/da3-t03-local-storage-registry.md)
- [DA3-T04 - Sensitive Data in Logs and Diagnostic Artifacts](da3-sensitive-data-exposure/da3-t04-logs-diagnostics.md)

## DA4 - Improper Cryptography Usage

- [DA4-T01 - Cryptographic Algorithms, Modes, Parameters, and Randomness](da4-improper-cryptography/da4-t01-algorithms-randomness.md)
- [DA4-T02 - Cryptographic Key Lifecycle and Protection](da4-improper-cryptography/da4-t02-key-lifecycle.md)
- [DA4-T03 - Password-Based Protection, Hashing, and Integrity Controls](da4-improper-cryptography/da4-t03-password-integrity.md)

## DA5 - Improper Authorization

- [DA5-T01 - Filesystem and Registry Authorization Boundaries](da5-improper-authorization/da5-t01-filesystem-registry.md)
- [DA5-T02 - Process, Service, UAC, and Privileged Operation Boundaries](da5-improper-authorization/da5-t02-process-service-privileges.md)
- [DA5-T03 - Local IPC Authentication and Authorization](da5-improper-authorization/da5-t03-local-ipc.md)

## DA6 - Security Misconfiguration

- [DA6-T01 - Installer, Updater, and Service Security Configuration](da6-security-misconfiguration/da6-t01-installer-updater-services.md)
- [DA6-T02 - File Handler, URI Scheme, Shell, and Parser Configuration](da6-security-misconfiguration/da6-t02-file-handler-uri-parser.md)
- [DA6-T03 - Supporting Services, Network Listeners, Firewall, and System Policy Configuration](da6-security-misconfiguration/da6-t03-supporting-services-policy.md)

## DA7 - Insecure Communication

- [DA7-T01 - Network Surface and Plaintext Protocol Discovery](da7-insecure-communication/da7-t01-network-surface-plaintext.md)
- [DA7-T02 - TLS, Certificate, Proxy, and Downgrade Validation](da7-insecure-communication/da7-t02-tls-certificate-proxy.md)
- [DA7-T03 - Message Integrity, Replay, and Session Binding](da7-insecure-communication/da7-t03-message-integrity-replay.md)

## DA8 - Poor Code Quality

- [DA8-T01 - DLL Hijacking and Unsafe Dependency Loading](da8-poor-code-quality/da8-t01-dll-hijacking.md)

## DA9 - Using Components with Known Vulnerabilities

- [DA9-T01 - Dependency and SBOM Hygiene](da9-vulnerable-components/da9-t01-dependency-sbom.md)

## DA10 - Insufficient Logging and Monitoring

Planned.

## Appendices

- [Quick Checklist](appendices/quick-checklist.md)
