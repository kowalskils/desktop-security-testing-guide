# Release Notes

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
