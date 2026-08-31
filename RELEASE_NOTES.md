# Release Notes

## Unreleased

- Organized test cases under `docs/` by primary OWASP Desktop Top 10 category and test case ID.
- Added a central testing guide index without changing existing test content.

## v0.16 - Message Integrity and Replay Resistance

Completes the primary DA7 set with DA7-T03 covering message authenticity, freshness, ordering, replay, session/user/tenant binding, broker authorization, offline queues, and idempotency.

## v0.15 - TLS and Certificate Validation

Adds DA7-T02 covering TLS policy, full certificate validation, client authentication, proxy and redirect behavior, custom callbacks, pinning, and downgrade resistance.

## v0.14 - Network Surface and Plaintext Protocols

Adds DA7-T01 covering complete connection discovery, process attribution, plaintext exposure, trust boundaries, alternate endpoints, and insecure protocol fallback.

## v0.13 - Supporting Services and System Policy

Completes the primary DA6 set with DA6-T03 covering supporting services, listeners, bind scope, firewall rules, default credentials, administration surfaces, Group Policy, Registry policy, and secure failure behavior.

## v0.12 - File Handler and Parser Configuration

Adds DA6-T02 covering file associations, URI schemes, shell commands, parser validation, content confusion, unsafe extraction, external references, and authorization after activation.

## v0.11 - Installer and Updater Configuration

Adds DA6-T01 covering secure installation defaults, authenticated updates, services, tasks, staging, elevation, downgrade, rollback, repair, and uninstall state.

## v0.10 - Local IPC Authorization

Completes the primary DA5 set with DA5-T03 covering named pipes, COM, RPC, local sockets, shared objects, Electron IPC, caller/server authentication, object authorization, impersonation, and replay.

## v0.9 - Privileged Process and Service Boundaries

Adds DA5-T02 covering process tokens, UAC manifests, services, tasks, privileged helpers, updater/install paths, caller reauthorization, replay, and controlled race testing.

## v0.8 - Filesystem and Registry Authorization

Adds DA5-T01 covering effective ACLs, inheritance, cross-user and cross-role access, trusted writable content, Registry views, and controlled authorization tampering.

## v0.7 - Password-Based Protection and Integrity

Completes the primary DA4 set with DA4-T03 covering password verifiers, password-derived encryption, salts, costs, peppers, MACs, signatures, tamper handling, resource limits, and cryptographic-format migration.

## v0.6 - Cryptographic Key Lifecycle

Adds DA4-T02 covering key inventory, generation, provisioning, storage, access, DPAPI scope, purpose separation, rotation, revocation, backup, recovery, migration, and destruction.

## v0.5 - Cryptographic Algorithms and Randomness

Adds DA4-T01 with repeatable inventory, algorithm, mode, parameter, IV/nonce, authenticated-encryption, tamper, randomness, downgrade, and migration tests for Windows desktop applications.

## v0.4 - Logs and Diagnostic Artifacts

This release completes the primary DA3 test set with a repeatable methodology for sensitive data exposed through logs, temporary files, clipboard operations, crash reports, telemetry queues, and support bundles.

### Added

- DA3-T04: Sensitive Data in Logs, Temporary Files, Clipboard, and Diagnostic Artifacts
- Success, failure, retry, debug, logout, update, crash, and support-workflow testing
- Structured-redaction, log-injection, clipboard-lifetime, temporary-file, WER dump, and support-bundle validation
- Permission, retention, consent, destination, cross-user, and cleanup criteria

### DA3 Coverage

- DA3-T01: Sensitive Data Exposure in Process Memory
- DA3-T02: Sensitive Data in Binaries and Application Resources
- DA3-T03: Sensitive Data in Local Storage and the Windows Registry
- DA3-T04: Sensitive Data in Logs, Temporary Files, Clipboard, and Diagnostic Artifacts

## v0.3 - Local Storage and Windows Registry Security

This release adds a repeatable methodology for validating sensitive-data protection, permissions, cryptographic scope, tamper resistance, and lifecycle cleanup in Windows local storage and the Registry.

### Added

- DA3-T03: Sensitive Data in Local Storage and the Windows Registry
- Process Monitor-driven discovery across install, use, logout, update, and uninstall workflows
- File and Registry inventory, ACL, cross-user, DPAPI-scope, and controlled tamper testing
- Native, .NET, Electron, SQLite, LevelDB, cache, backup, journal, and temporary-artifact coverage
- Evidence and pass/fail criteria for confidentiality, authorization, integrity, and retention

### Included Coverage

- DA3-T01: Sensitive Data Exposure in Process Memory
- DA3-T02: Sensitive Data in Binaries and Application Resources
- DA8-T01: DLL Hijacking and Unsafe Dependency Loading (draft)
- DA9-T01: Dependency and SBOM Hygiene

## v0.2 - Binary and Resource Inspection

This release adds a repeatable Windows-focused methodology for detecting and validating sensitive data exposed through distributed application artifacts.

### Added

- DA3-T02: Sensitive Data in Binaries and Application Resources
- Native PE and resource inspection workflow
- .NET assembly, metadata, resource, and configuration analysis
- Electron ASAR, source map, preload, and unpacked-resource inspection
- Candidate-secret classification, controlled validation, and cross-installation comparison
- Evidence and pass/fail criteria distinguishing public metadata from reusable secrets

### Included Coverage

- DA3-T01: Sensitive Data Exposure in Process Memory
- DA8-T01: DLL Hijacking and Unsafe Dependency Loading (draft)
- DA9-T01: Dependency and SBOM Hygiene

## v0.1 - Process Memory Analysis

This release establishes the first versioned milestone of the Desktop Security Testing Guide.

### Added

- DA3-T01: Sensitive Data Exposure in Process Memory
- Repeatable state-based memory testing for input, active use, view closure, logout, timeout, and revocation
- Synthetic marker design, evidence requirements, and pass/fail criteria
- Windows-focused guidance for native Win32, .NET, and Electron applications
- OWASP Desktop Top 10 coverage matrix and test case identifiers

### Included Coverage

- DA8-T01: DLL Hijacking and Unsafe Dependency Loading (draft)
- DA9-T01: Dependency and SBOM Hygiene

Memory dumps may contain sensitive data and must be captured only with authorization, stored with appropriate access controls, and disposed of according to the assessment's evidence-retention requirements.
