# Desktop Security Testing Guide (based on OWASP Top 10 Desktop Application Security Risks)

### Description
Although OWASP provides testing guides for web and mobile applications, there is currently no comprehensive, structured methodology for assessing the security of Windows desktop applications. Organizations developing thick-client applications lack vendor-neutral best practices and repeatable testing procedures, leading to inconsistent security assessments and preventable vulnerabilities.

This project addresses the gap between the OWASP Desktop Application Security Top 10 and real-world security testing practice, as well the lack of a proper security testing guide for these applications.

No current OWASP project delivers this as a security testing methodology

## Why This Project Exists
Desktop applications remain critical across industries such as:
- Finance
- Healthcare
- Industrial software
- Security tooling
- Enterprise internal systems

However, security testing for these applications is often:
- Ad-hoc
- Tool-driven without methodology
- Dependent on undocumented tribal knowledge

This leads to:
- Inconsistent assessments
- Missed vulnerabilities
- High-impact local and supply-chain security risks

### OWASP Email Address
Related OWASP email address: **luis.stefan@owasp.org**

Related Top Ten: https://owasp.org/www-project-desktop-app-security-top-10/


## Project Purpose
The purpose of this project is to produce a practical, repeatable, and accessible security testing methodology for Windows desktop applications, designed for:
- Penetration testers
- Red teamers
- Application security engineers
- Software engineers building secure desktop software

## Testing Guide Approach

The OWASP Desktop Application Security Top 10 defines risk categories. This project complements that awareness material with executable security test cases for Windows desktop applications.

Each test case is intended to answer four practical questions:

1. What security property is being validated?
2. How can a tester exercise that property safely and repeatably?
3. What evidence demonstrates that the control is effective or ineffective?
4. What result should be reported, and how should the weakness be remediated?

A complete test case should include its OWASP Desktop Top 10 mapping, scope, objective, threat model, prerequisites, tools, step-by-step methodology, evidence to collect, pass/fail criteria, expected findings, remediation guidance, and references. Tool output alone is not considered a confirmed finding.

## OWASP Desktop Top 10 Coverage

| Category | Risk | Planned or Available Test Coverage | Status |
| --- | --- | --- | --- |
| DA1 | Injections | Database, OS command, LDAP, XML, XPath, and rendered-content injection | Planned |
| DA2 | Broken Authentication and Session Management | Authentication boundaries, local and remote sessions, logout, timeout, reauthentication, and external authenticators | Planned |
| DA3 | Sensitive Data Exposure | [Process memory](docs/da3-sensitive-data-exposure/da3-t01-process-memory.md); [binaries and resources](docs/da3-sensitive-data-exposure/da3-t02-binaries-resources.md); [local storage and Registry](docs/da3-sensitive-data-exposure/da3-t03-local-storage-registry.md); [logs and diagnostics](docs/da3-sensitive-data-exposure/da3-t04-logs-diagnostics.md) | Covered |
| DA4 | Improper Cryptography Usage | [Algorithms and randomness](docs/da4-improper-cryptography/da4-t01-algorithms-randomness.md); [key lifecycle](docs/da4-improper-cryptography/da4-t02-key-lifecycle.md); [password protection and integrity](docs/da4-improper-cryptography/da4-t03-password-integrity.md) | Covered |
| DA5 | Improper Authorization | [Filesystem and Registry](docs/da5-improper-authorization/da5-t01-filesystem-registry.md); [process and service privileges](docs/da5-improper-authorization/da5-t02-process-service-privileges.md); [local IPC](docs/da5-improper-authorization/da5-t03-local-ipc.md) | Covered |
| DA6 | Security Misconfiguration | [Installer, updater, and services](docs/da6-security-misconfiguration/da6-t01-installer-updater-services.md); [file handlers and parsers](docs/da6-security-misconfiguration/da6-t02-file-handler-uri-parser.md); [supporting services and policy](docs/da6-security-misconfiguration/da6-t03-supporting-services-policy.md) | Covered |
| DA7 | Insecure Communication | [Network surface and plaintext](docs/da7-insecure-communication/da7-t01-network-surface-plaintext.md); [TLS and certificates](docs/da7-insecure-communication/da7-t02-tls-certificate-proxy.md); [message integrity and replay](docs/da7-insecure-communication/da7-t03-message-integrity-replay.md) | Covered |
| DA8 | Poor Code Quality | [DLL hijacking](docs/da8-poor-code-quality/da8-t01-dll-hijacking.md); [binary hardening and release integrity](docs/da8-poor-code-quality/da8-t02-binary-hardening-code-signing.md); [memory safety, fuzzing, and crash triage](docs/da8-poor-code-quality/da8-t03-memory-safety-fuzzing-crash-triage.md) | Covered |
| DA9 | Using Components with Known Vulnerabilities | [Dependency and SBOM hygiene](docs/da9-vulnerable-components/da9-t01-dependency-sbom.md); [package sources and restore integrity](docs/da9-vulnerable-components/da9-t02-package-source-restore-integrity.md); [vulnerability applicability and remediation](docs/da9-vulnerable-components/da9-t03-vulnerability-applicability-remediation.md) | Covered |
| DA10 | Insufficient Logging and Monitoring | [Security event coverage and correlation](docs/da10-insufficient-logging-monitoring/da10-t01-security-event-coverage-correlation.md); [log integrity and failure resilience](docs/da10-insufficient-logging-monitoring/da10-t02-log-integrity-failure-resilience.md); [forwarding and alerts](docs/da10-insufficient-logging-monitoring/da10-t03-forwarding-alert-validation.md) | Covered |

The mapping is intentionally many-to-many. For example, DLL hijacking may provide evidence for DA8, DA5, and DA6 depending on whether the root cause is unsafe loading behavior, weak permissions, or an insecure installation configuration.

Covered means the currently planned test set is documented, not that the category is exhaustive or that an application has passed security validation.

### Test Case Identifiers

Test cases use the format `DAx-Tyy`, where `DAx` is the primary OWASP Desktop Top 10 category and `Tyy` is a sequential test number within that category. Secondary category mappings should be recorded when a test validates more than one risk class.


### Project Deliverables*
This project will provide a structured Security Testing Guide (similar format to OWASP WSTG and MSTG) for Desktop (Windows .NET) applications.
- Windows-specific security testing workflows 
- Tools and repeatable test procedures 
- Remediation patterns developers can apply immediately

Covering step-by-step security tests for:
-	Memory analysis
-	Binary & resource inspection
-	DLL hijacking risk validation
-	Local storage and registry security
-	Dependency and SBOM hygiene

## Documentation Versioning

Documentation releases use lightweight version tags. Each meaningful new testing chapter should be accompanied by a new version tag and concise GitHub release notes describing the added coverage. Draft and local working changes are reviewed before a tag or release is published.

Release notes are maintained in [RELEASE_NOTES.md](RELEASE_NOTES.md).

The complete testing guide index is available in [docs/README.md](docs/README.md).

License https://creativecommons.org/licenses/by-sa/4.0/ - CC BY-SA
