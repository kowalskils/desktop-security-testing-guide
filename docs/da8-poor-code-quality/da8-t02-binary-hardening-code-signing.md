# Binary Hardening, Code Signing, and Release Integrity

| Field | Value |
| --- | --- |
| Test Case ID | DA8-T02 |
| Primary OWASP Category | DA8 - Poor Code Quality |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA6 - Security Misconfiguration |
| Platforms | Native PE, .NET, Electron, installers, updaters, services, and drivers on Windows |

## Scope and Objective

This test validates whether release binaries enable applicable Windows exploit mitigations, carry trustworthy and time-valid signatures, preserve integrity across packaging and update workflows, and exclude unintended debug or development characteristics. A missing mitigation is evaluated in the context of architecture, compiler, runtime, threat model, and reachable unsafe code; it is not automatically a standalone vulnerability.

## Prerequisites and Tools

- Obtain the exact installer and installed artifacts; record SHA-256 hashes, versions, architectures, and sources.
- Use Sigcheck, PowerShell, PE/load-configuration inspection, approved compiler/linker tools, and Windows Exploit Protection reporting.
- Test in an isolated lab and do not submit proprietary binaries to public services.

## Testing Methodology

1. Inventory every first-party EXE, DLL, driver, native Node module, COM server, installer, updater, service, and privileged helper.
2. Record Authenticode status, signer, chain, timestamp, digest algorithm, catalog membership, and whether the signature remains valid after certificate expiry under the intended policy.
3. Compare installer contents with installed files and the vendor manifest; identify unsigned, differently signed, or unexpectedly modified components.
4. Inspect applicable PE characteristics and load configuration for ASLR/high-entropy ASLR, DEP/NX, Control Flow Guard, CET/Shadow Stack compatibility, SafeSEH where relevant, relocation data, stack protection indicators, and architecture-specific mitigations.
5. Verify managed applications do not rely on managed-code assumptions while shipping reachable unsafe/native modules without equivalent review.
6. Test controlled one-byte modification, wrong signer, invalid timestamp, corrupted catalog, and substituted benign module against installer, updater, plug-in, and self-integrity checks.
7. Confirm integrity is checked before privileged loading or execution and that failure does not silently continue, downgrade, or fetch from an untrusted source.
8. Review production packages for PDBs, source maps, assertions, test hooks, debug runtimes, verbose exception behavior, and development-only bypasses; validate security impact before reporting.
9. Compare x86, x64, ARM64, per-user, per-machine, and release-channel artifacts because hardening may differ.

## Evidence to Collect

Artifact inventory and hashes; signature/chain/timestamp output; PE mitigation matrix; compiler/runtime evidence when supplied; modified/substituted artifact results; privileged consumer; architecture/channel comparison; and any accepted compatibility exception.

## Pass/Fail Criteria

### Pass

Applicable mitigations are consistently enabled, release artifacts have verifiable provenance and integrity, privileged consumers reject unauthorized modification before use, and production packages exclude dangerous development behavior.

### Fail

Fail when a reachable native attack surface lacks a required mitigation without an effective compensating control, signatures are missing or not verified across a trust boundary, modified code is accepted for privileged execution, update/package integrity can be bypassed, or a production test/debug feature creates a demonstrated security bypass.

### Needs Further Investigation

Use when mitigation applicability, compiler behavior, signature policy, catalog trust, native-code reachability, or the security effect of a development artifact cannot be established.

## Remediation Guidance

- Enable supported compiler/linker mitigations for every architecture and native module.
- Sign installers, executables, libraries, drivers, catalogs, and updates with protected keys and trusted timestamps.
- Verify provenance and integrity before privileged use; authenticate manifests and version metadata.
- Maintain a release mitigation/signature baseline and fail builds on regression.
- Remove unnecessary symbols, test hooks, debug runtimes, and bypass configuration from production packages.

## References

- [Microsoft Sysinternals: Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)
- [Microsoft: PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft: Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)
- [Microsoft: SignTool](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/signtool)
