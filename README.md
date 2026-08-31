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
| DA3 | Sensitive Data Exposure | [Sensitive data exposure in process memory](mem-analysis.md); [sensitive data in binaries and application resources](binary-and-resource-inspection.md); [sensitive data in local storage and the Windows Registry](local-storage-and-registry-security.md); [logs, temporary files, clipboard, and diagnostic artifacts](logs-temporary-files-and-support-artifacts.md) | Covered |
| DA4 | Improper Cryptography Usage | [Cryptographic algorithms, modes, parameters, and randomness](cryptographic-algorithms-modes-and-randomness.md); [cryptographic key lifecycle and protection](cryptographic-key-lifecycle.md); [password-based protection, hashing, and integrity controls](password-based-protection-and-integrity.md) | Covered |
| DA5 | Improper Authorization | File and registry ACLs, process and service privileges, role enforcement, privileged operations, and local IPC authorization | Planned |
| DA6 | Security Misconfiguration | Named pipes, services, file handlers, firewall rules, registry settings, installers, update paths, and supporting services | Planned |
| DA7 | Insecure Communication | Protocol discovery, TLS validation, certificate validation, downgrade resistance, proxy behavior, and replay testing | Planned |
| DA8 | Poor Code Quality | [DLL hijacking and unsafe dependency loading](dll-hijacking.md), binary protections, code signing, unsafe memory behavior, and release-artifact review | Draft |
| DA9 | Using Components with Known Vulnerabilities | [Dependency and SBOM hygiene](dependency-and-sbom-hygiene.md) | Available |
| DA10 | Insufficient Logging and Monitoring | Security event coverage, log integrity, sensitive-data exclusion, auditability, alerting, and tamper resistance | Planned |

The mapping is intentionally many-to-many. For example, DLL hijacking may provide evidence for DA8, DA5, and DA6 depending on whether the root cause is unsafe loading behavior, weak permissions, or an insecure installation configuration.

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

License https://creativecommons.org/licenses/by-sa/4.0/ - CC BY-SA
