# Dependency and SBOM Hygiene

| Field | Value |
| --- | --- |
| Test Case ID | DA9-T01 |
| Primary OWASP Category | DA9 - Using Components with Known Vulnerabilities |
| Secondary Categories | DA5 - Improper Authorization; DA6 - Security Misconfiguration; DA8 - Poor Code Quality |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This document provides a repeatable methodology for identifying and assessing risks introduced by third-party and first-party dependencies in Windows desktop applications. It covers dependency inventory, Software Bill of Materials (SBOM) validation, component provenance, known-vulnerability review, and update behavior.

It applies to:

- Native Win32 applications and their bundled libraries
- .NET applications, including WinForms, WPF, and mixed-mode applications
- Electron-based Windows applications and packaged Node.js modules
- Installers, updaters, plug-ins, drivers, and other components distributed with the application

This document focuses on security testing and risk identification. Finding an outdated component is not sufficient by itself to demonstrate exploitability; the affected functionality, application configuration, and reachable attack surface must also be considered.

## Objective

The objectives of this test are to determine whether:

- The application owner maintains a complete and accurate inventory of shipped components.
- The supplied SBOM represents the installed application and its transitive dependencies.
- Dependencies originate from trusted sources and retain their expected integrity and signatures.
- Known vulnerabilities are identified, triaged, and remediated based on reachability and business risk.
- Unsupported or end-of-life components are not included without documented compensating controls.
- Build and release processes detect unexpected dependency changes.
- Application updates replace vulnerable components without introducing downgrade or rollback risks.

## Threat Model

The test considers attackers who may:

- Exploit a known vulnerability in a bundled dependency.
- Introduce a malicious or compromised package through a public or private package source.
- Replace a dependency in a user-writable installation or update location.
- Abuse a dependency-confusion, namespace-collision, or package-substitution condition during the build process.
- Target an unmaintained component that no longer receives security updates.
- Conceal a vulnerable transitive dependency that is absent from an incomplete SBOM.

Potential impacts include arbitrary code execution, privilege escalation, information disclosure, application compromise, persistence, and supply-chain compromise affecting multiple releases or customers.

## Prerequisites and Safety

- Obtain the exact installer, package, or release build under assessment.
- Record the application version, installer version, architecture, download source, and cryptographic hashes.
- Use an isolated Windows test environment when installing or executing untrusted software.
- Preserve the original package so that extracted and installed files can be compared with the distributed artifact.
- Obtain the vendor-provided SBOM, dependency lock files, and build metadata when available.
- Do not upload proprietary binaries, hashes, or SBOMs to public services without authorization.

## Tools

Select tools appropriate to the application technology and assessment constraints:

1. **Syft**
   - Generates SBOMs from directories, archives, containers, and supported package formats.
   - Useful for creating an independent inventory to compare with vendor documentation.

2. **Microsoft SBOM Tool**
   - Generates SPDX SBOMs and can integrate with Windows-oriented build and release workflows.

3. **OSV-Scanner, Grype, or Dependency-Track**
   - Correlates identified packages with known-vulnerability data.
   - Results require validation because package identity, configuration, and code reachability affect risk.

4. **Sigcheck and PowerShell**
   - Verifies Authenticode signatures, hashes, file versions, and signer information for PE files.

5. **NuGet tooling and `dotnet` CLI**
   - Reviews direct and transitive dependencies for .NET applications when project or lock files are available.

6. **npm, pnpm, or Yarn tooling**
   - Reviews Electron and Node.js dependency trees and lock files when source artifacts are available.

7. **Process Monitor and Process Explorer**
   - Confirms which libraries and modules are accessed or loaded at runtime.

Tool output is evidence, not a final finding. Verify component identity and affected behavior before assigning severity.

## Testing Methodology

### Step 1 - Establish the Release Baseline

1. Record the source and version of the application package.
2. Calculate hashes for the original artifact:

```powershell
Get-FileHash -Algorithm SHA256 ".\ApplicationInstaller.exe"
```

3. Inspect the package's Authenticode signature:

```powershell
Get-AuthenticodeSignature ".\ApplicationInstaller.exe" |
    Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

4. Record the signer, timestamp status, architecture, and release channel.
5. Confirm that the package was obtained from an approved distribution location.

### Step 2 - Enumerate Shipped Components

1. Extract the installer where the package format and authorization allow it.
2. Inventory the extracted package and the installed application directory.
3. Include executables, DLLs, assemblies, drivers, plug-ins, runtime frameworks, Electron archives, and updater components.
4. Record, where available:
   - Component name and version
   - Package manager and package identifier
   - File path and SHA-256 hash
   - Supplier and license
   - Authenticode signer
   - Direct or transitive relationship
5. Treat duplicated libraries and multiple versions as separate inventory entries.

For PE files, collect version and signature information with PowerShell:

```powershell
Get-ChildItem "C:\Program Files\Vendor\Application" -Recurse -File |
    Where-Object { $_.Extension -in '.exe', '.dll', '.sys' } |
    ForEach-Object {
        $signature = Get-AuthenticodeSignature $_.FullName
        [PSCustomObject]@{
            Path = $_.FullName
            FileVersion = $_.VersionInfo.FileVersion
            ProductVersion = $_.VersionInfo.ProductVersion
            SignatureStatus = $signature.Status
            Signer = $signature.SignerCertificate.Subject
        }
    }
```

File-version metadata can be missing, inaccurate, or vendor-defined. Corroborate it with package metadata, hashes, and SBOM evidence.

### Step 3 - Identify Technology-Specific Dependencies

#### Native Win32

- Enumerate imported and delay-loaded DLLs.
- Identify statically linked libraries that may not appear as separate files.
- Review bundled runtimes, codecs, database engines, cryptographic libraries, drivers, and installer components.
- Use runtime observation to distinguish shipped components from Windows system components.

#### .NET

- Inventory managed assemblies and native libraries used through P/Invoke or mixed-mode code.
- Review `.deps.json`, `packages.lock.json`, project files, and NuGet metadata when supplied.
- Identify bundled .NET runtimes and self-contained deployment components.
- Record transitive packages and assembly versions; do not rely only on top-level package references.

When project artifacts are available, use the SDK command supported by the installed .NET version to list vulnerable packages, including transitive dependencies.

#### Electron

- Identify the Electron, Chromium, and Node.js versions shipped with the application.
- Inspect `app.asar`, `package.json`, and the applicable lock file when authorized and available.
- Inventory native Node modules separately because they may contain platform-specific binary dependencies.
- Review production dependencies rather than relying solely on a development-tree audit.

### Step 4 - Generate and Validate the SBOM

1. Obtain the vendor-generated SBOM, if available.
2. Confirm its format and declared specification version, such as SPDX or CycloneDX.
3. Generate an independent SBOM from the release artifact or installed directory.
4. Compare the two inventories and investigate:
   - Components present in the application but absent from the SBOM
   - Components listed in the SBOM but absent from the release
   - Missing versions, suppliers, hashes, licenses, or dependency relationships
   - Incorrect package identifiers or package URLs
   - Unresolved transitive dependencies
5. Confirm that the SBOM identifies the exact application release and can be associated with its artifact hash.
6. Check whether the SBOM is regenerated for each meaningful release and protected from unauthorized modification.

An SBOM is not complete merely because it conforms to a schema. Its contents must accurately represent the released artifact.

### Step 5 - Correlate Components with Known Vulnerabilities

1. Scan the independently generated SBOM with an approved vulnerability-analysis tool.
2. Review vendor advisories and authoritative vulnerability sources for high-risk components.
3. Validate each candidate finding:
   - Is the package and version match correct?
   - Is the affected component actually shipped or loaded?
   - Is the vulnerable feature present and reachable?
   - Does application configuration mitigate or expose the condition?
   - Is an upstream fix or vendor-supported backport available?
4. Record the vulnerability identifier, affected component, evidence, exploit prerequisites, fix version, and confidence level.
5. Use known-exploited status, exploit maturity, privileges required, exposure, and business impact to support prioritization rather than relying on a base score alone.

### Step 6 - Assess Provenance and Integrity

1. Verify Authenticode signatures for signed executables, DLLs, and drivers.
2. Compare component hashes with trusted build records, lock files, or vendor manifests.
3. Review whether package sources are explicitly configured and trusted.
4. When build artifacts are available, verify that:
   - Dependency versions are pinned or resolved through committed lock files.
   - Private package namespaces cannot be silently resolved from public repositories.
   - Package integrity checks are enforced.
   - Build credentials and package-source tokens are not embedded in artifacts.
   - Dependency updates are reviewed and produce an auditable inventory change.
5. Flag unexpected unsigned binaries based on context; unsigned status alone does not prove maliciousness.

### Step 7 - Review Support and Update Posture

1. Identify dependencies that are end-of-life, archived, abandoned, or outside their supported release window.
2. Determine whether security fixes are regularly incorporated into supported application versions.
3. Review the desktop application's updater and installer behavior:
   - Updates are authenticated before installation.
   - Vulnerable components are removed or replaced rather than left in loadable locations.
   - Standard users cannot replace packages in staging or installation directories.
   - Downgrade to a vulnerable release is prevented or explicitly controlled.
4. Re-run the inventory after an update and confirm that remediated components are no longer present or loadable.

### Step 8 - Confirm Runtime Relevance

1. Exercise representative application workflows in an isolated environment.
2. Use Process Monitor or Process Explorer to observe loaded libraries and accessed component paths.
3. Map runtime evidence back to the SBOM and vulnerability results.
4. Do not automatically dismiss a component because it was not observed during one test path; it may be loaded only by another feature, plug-in, architecture, or error condition.

### Step 9 - Document and Report Findings

For each confirmed issue, record:

- Affected application release and artifact hash
- Component name, version, path, supplier, and hash
- Source of component-identification evidence
- Vulnerability or support-status references
- Runtime reachability and relevant application configuration
- Attack prerequisites and likely impact
- Recommended fixed version or removal strategy
- Any compensating controls and their limitations

Avoid reporting scanner output without validation. Clearly distinguish confirmed vulnerabilities, inventory-quality defects, unsupported-component risks, and items requiring further investigation.

## Evidence to Collect

Retain enough evidence for another tester to reproduce the result without exposing proprietary artifacts unnecessarily:

- Application and installer versions, architecture, source, and SHA-256 hashes
- Authenticode status, signer, and timestamp information
- The vendor-supplied SBOM and independently generated SBOM
- Component names, versions, package identifiers, file paths, and hashes
- Lock files, package-source configuration, and relevant build metadata when available
- Vulnerability-tool output together with authoritative advisory references
- Runtime module or file-access observations for the exercised workflows
- Installation, update, cache, and staging-directory ACLs
- Evidence of the installed state before and after an application update
- Tester validation notes covering reachability, prerequisites, impact, and confidence

Screenshots may support a result, but structured text exports, hashes, and saved tool output are preferable when they make comparison and retesting easier.

## Pass/Fail Criteria

### Pass

The test passes when the released artifact has an accurate and traceable component inventory; identified components have trustworthy provenance; known vulnerabilities and unsupported dependencies are subject to documented, risk-based treatment; dependency and update locations are protected; and no confirmed reachable dependency vulnerability remains without an accepted and effective control.

### Fail

The test fails when one or more of the following conditions are confirmed:

- A shipped or loadable component cannot be identified or is materially misrepresented in the SBOM.
- A known vulnerable component is reachable in the tested application context and lacks an effective mitigation or verified fix. A remediation plan alone does not resolve the technical finding.
- A supported product includes an end-of-life dependency without documented, time-bound risk treatment.
- Component provenance or integrity cannot be established where it is required for the release process.
- A standard user can replace or tamper with a component used by the application or updater.
- Update behavior leaves a vulnerable copy loadable or permits an uncontrolled downgrade to a known-vulnerable release.

### Needs Further Investigation

Use this outcome when package identity, affected configuration, code reachability, or vendor backport status cannot be established with the available evidence. Do not convert an unverified scanner match into a confirmed vulnerability.

Use [DA9-T03](da9-t03-vulnerability-applicability-remediation.md) for detailed applicability, backport, VEX, and deployed-remediation validation.

## Expected Findings

### Secure or Expected Conditions

- The SBOM maps to the exact released artifact and includes direct and transitive dependencies.
- Component versions, hashes, suppliers, licenses, and relationships are sufficiently complete for investigation.
- Dependencies come from approved sources and match trusted build or release records.
- Known vulnerabilities are continuously triaged and remediated according to documented risk criteria.
- Supported application releases do not bundle unsupported components without explicit risk treatment.
- Install and update locations are protected from modification by standard users.
- Security updates replace vulnerable components and cannot be trivially downgraded.

### Potential Findings

- A shipped or runtime-loaded component is missing from the SBOM.
- The SBOM contains incorrect versions, stale entries, or unresolved transitive dependencies.
- A dependency has a confirmed reachable vulnerability with no effective mitigation.
- An end-of-life runtime or library remains in a supported application release.
- Dependency versions are not pinned, or release builds do not use the reviewed lock file.
- Private package names can resolve from an untrusted public source.
- A bundled component has an unexpected signature, hash, supplier, or origin.
- Multiple vulnerable copies remain after an application update.
- A standard user can modify a dependency, update cache, or package staging directory.
- The application can be downgraded to a release containing known vulnerable components.

## Remediation Guidance

- Generate an SPDX or CycloneDX SBOM for every release and bind it to the release artifact using hashes and protected build metadata.
- Inventory transitive, statically linked, bundled-runtime, installer, updater, plug-in, and native dependencies.
- Pin dependency versions, commit lock files, enforce integrity checks, and restrict package sources.
- Define an ownership and remediation process for vulnerable and unsupported components.
- Prioritize remediation using reachability, exploitability, known exploitation, application exposure, and business impact.
- Replace end-of-life components or document time-bound compensating controls and migration plans.
- Sign release artifacts and protect installation, update, cache, and staging directories with appropriate Windows ACLs.
- Authenticate updates and implement controlled rollback behavior that does not permit silent downgrade to known-vulnerable releases.
- Retain historical SBOMs and dependency changes so releases can be investigated after a new vulnerability is disclosed.

## References

- [OWASP CycloneDX Software Bill of Materials](https://owasp.org/www-project-cyclonedx/)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool)
- [Microsoft: Software Bill of Materials](https://www.microsoft.com/en-us/securityengineering/sbom)
- [CISA: Software Bill of Materials](https://www.cisa.gov/sbom)
- [SPDX Specification](https://spdx.dev/use/specifications/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [Open Source Vulnerabilities database](https://osv.dev/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft: Get-AuthenticodeSignature](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature)
