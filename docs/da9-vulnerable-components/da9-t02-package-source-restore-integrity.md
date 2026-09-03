# Package Source Selection and Dependency Restore Integrity

| Field | Value |
| --- | --- |
| Test Case ID | DA9-T02 |
| Primary OWASP Category | DA9 - Using Components with Known Vulnerabilities |
| Secondary Categories | DA6 - Security Misconfiguration; DA8 - Poor Code Quality |
| Platforms | Windows desktop build and release workflows: NuGet/.NET, npm/Electron, and native dependencies |

## Scope

This test validates the acquisition boundary between approved dependency definitions and the components restored for a desktop release. It extends [DA9-T01](da9-t01-dependency-sbom.md) with controlled tests of source selection, locked restoration, integrity enforcement, and cache trust.

Source substitution is a supply-chain condition, not proof of a known CVE. Report the root cause under DA6 or DA8 where appropriate and use DA9-T01 for known-vulnerability assessment. Runtime DLL loading and application updates are covered by [DA8-T01](../da8-poor-code-quality/da8-t01-dll-hijacking.md) and [DA6-T01](../da6-security-misconfiguration/da6-t01-installer-updater-services.md).

## Objective and Threat Model

Determine whether a build accepts a dependency from an unauthorized source, changes a reviewed dependency graph without approval, or consumes altered bytes from a less-trusted cache.

Define which inputs an attacker can control: an external feed, a shared cache, a proposed dependency change, or an upstream archive. Keep these capabilities separate. An attacker who can already rewrite both the approved lock file and its integrity values is not testing the same boundary as a feed-only attacker.

## Prerequisites and Safety

- Obtain the build revision, dependency manifests, lock files, effective source configuration, tool versions, and release restore command.
- Use a disposable Windows workspace or VM without production credentials, signing keys, or publishing permissions.
- Configure two lab-only feeds representing approved and unapproved sources. Use invented package names and harmless fixtures with distinct content hashes. Never register real private package names on a public registry.
- Block unapproved outbound traffic. Some tools perform audit, metadata, or auxiliary binary downloads independently of the main restore source.
- Use fresh, explicitly selected lab caches; do not clear shared developer or CI caches.
- Review fixture contents before restoration. Disable install scripts where supported during source-selection testing. Restore and build tooling can execute code; this is not a safe way to inspect an untrusted real project.
- If source/build access is unavailable, document that limitation and continue artifact assessment with DA9-T01. An installed binary alone cannot establish restore policy.

## Tools

Use the application's pinned package manager, lab feed access logs, file hashes, configuration diffs, dependency graph exports, and approved network/process observation. Record command exit codes as well as logs. Redact credentials and private package names before sharing evidence.

## Testing Methodology

### Step 1 - Capture the Effective Build Policy

1. Record the exact restore invocation, account, working directory, SDK/package-manager version, and target architecture/runtime.
2. Review repository, user, machine, environment, and command-line configuration layers. Identify every source, mirror, proxy, credential provider, cache, and fallback location.
3. Identify where source routing, versions, and expected hashes are approved and how changes reach the release build.
4. Include transitive packages, build tools, native archives, and downloads performed outside the package manager. A registry-only inventory may miss Electron binaries or native build inputs.
5. Save sanitized configuration and baseline manifest/lock hashes. Do not dump environment variables or credential configuration wholesale.

### Step 2 - Establish a Clean Positive Control

1. Create harmless fixture packages in the approved lab feed, including a direct dependency and a transitive dependency.
2. Adapt a disposable copy of the actual build's routing and restore policy to the fixtures. Record every difference from production.
3. Restore with an empty lab cache. Confirm the selected source through feed logs and restored content hashes, not merely a success message.
4. Repeat without changing manifests, lock data, or policy. Compare the resolved graph and package bytes. This tests dependency consistency, not byte-for-byte reproducibility of the final executable.
5. Preserve a separate warm-cache state for Step 5.

### Step 3 - Exercise Source Selection

Run one change at a time, from the clean baseline:

| Controlled change | Required observation |
| --- | --- |
| Same fixture ID/version on both feeds, with different bytes | Approved source and expected hash remain selected; an unauthorized candidate is not accepted |
| Higher candidate version on the unapproved feed | Routing and version policy still constrain resolution |
| Approved feed unavailable, alternate feed available | No silent fallback to an unauthorized source |
| Transitive fixture available only from the unapproved feed | The same trust policy applies to transitive dependencies |
| Unexpected source inherited from user/machine settings | Release configuration excludes it or demonstrably prevents its use |

Do not assume feed order determines precedence or that every ecosystem selects the highest version. Record the resolver's actual decision. A network request alone proves contact, not package acceptance; record metadata leakage separately from substitution.

### Step 4 - Challenge Lock and Integrity Enforcement

1. In a fresh test copy, change a manifest dependency while retaining the approved lock file. Run the release restore command and verify it rejects inconsistent inputs instead of silently rewriting the lock.
2. Test a missing lock file if the release policy requires one. Confirm the release gate does not silently generate and accept new resolution data.
3. Serve a structurally valid fixture with modified content at the same lab package identity while keeping the original trusted integrity value. Verify rejection and record the specific diagnostic.
4. Distinguish integrity mismatch from archive corruption, connectivity failure, or authentication failure. Restore the original bytes and verify the positive control succeeds.
5. Inspect repository and workspace diffs after each attempt. A successful command that changes reviewed dependency data is not a successful locked restore.
6. Treat mutable Git references, direct URLs, local paths, and native download scripts separately; determine what fixes their identity and authenticates their bytes.

### Step 5 - Test Cache Trust Separately

1. Compare empty-cache and warm-cache results with identical configuration.
2. In a disposable cache only, prepopulate the fixture from the unapproved lab source, then run restoration with the approved policy.
3. Record whether the cached object is reused, checked, rejected, or fetched again. A source-routing rule may not revalidate already-cached packages.
4. Establish who can write production cache entries. Reuse is a security finding when a less-trusted writer can supply accepted release inputs, not simply because caching occurs.
5. Inspect whether untrusted pull-request jobs and trusted release jobs share writable cache locations or credentials.

### Step 6 - Apply Ecosystem-Specific Checks

#### NuGet and .NET

- Review Package Source Mapping for direct and transitive IDs, specificity, overlapping patterns, and all client versions used by developers and CI.
- Test with an empty global-packages directory: an existing package can bypass source lookup and mapping.
- Do not treat mapping as a privacy boundary for every metadata command. Review outbound requests independently.
- For PackageReference projects using an approved packages.lock.json, test locked restoration. Review older packages.config workflows separately.

Example for a reviewed disposable fixture, with an existing lock file and lab-only NuGet.Config:

~~~powershell
dotnet restore .\Fixture.csproj --locked-mode --configfile .\NuGet.Config --packages .\lab-packages
~~~

Start each cold-cache scenario with a new fixture directory. Validate audit sources and network restrictions before running; this command is not a sandbox.

#### npm and Electron

- Inspect scope-to-registry mappings, the default registry, lock-file resolved locations, and direct URL/Git dependencies.
- Verify tokens are scoped to the intended registry host/path; use synthetic credentials if testing delivery.
- Use the exact npm version and flags expected by CI. For npm-based locked installs, test npm ci with an existing lock file.
- During routing tests, use npm ci --ignore-scripts --no-audit --no-fund in a disposable fixture. It removes existing node_modules, so do not use the developer's working directory.
- Disabling scripts limits this test's coverage. Inspect separately authorized build/install hooks and Electron/native downloads; do not claim the full build was validated by a script-disabled run.

#### Native Build Inputs

- For vcpkg, record registry revisions, manifest baseline, overrides, overlays, and binary-cache configuration. A baseline is a minimum version policy, not an exact lock for every dependency.
- For other native acquisition mechanisms, trace pinned revisions, archive hashes, mirrors, and custom download steps using the actual tool's documented behavior.
- Include statically linked inputs and build-time generators, even when they do not remain as separate installed files.

### Step 7 - Retest and Connect to the Release

Repeat every failed scenario after remediation, plus the positive control. Confirm the reviewed policy is used by the real release job, not just a developer's shell. Compare the restored inventory with the release SBOM and record unresolved packaging differences.

Remove only lab fixtures and synthetic credentials, or revert the VM snapshot. Retain sanitized evidence and document any workflow not exercised.

## Evidence to Collect

Retain build revision; tool versions; sanitized effective configuration; manifest and lock hashes; fixture identities and hashes; feed request logs; cache state and ownership; exact invocation and exit code; selected package bytes; configuration/workspace diffs; and before/after remediation results. For each finding, identify the attacker-controlled input and the protected build stage that accepted it.

## Pass/Fail Criteria

### Pass

For the tested release workflow, dependencies come only from authorized sources or protected caches, approved resolution data is enforced, altered package bytes are rejected where integrity is required, and negative tests cannot silently change release inputs. State scope and exceptions.

### Fail

Fail for demonstrated unauthorized source selection, acceptance of altered dependency bytes across the defined boundary, silent lock-policy bypass, or consumption of a less-trusted cache entry by a protected release job. Explain whether the test proved package acceptance, build execution, or shipped inclusion; do not equate them.

### Needs Further Investigation

Use when only configuration concerns are visible, fixtures diverge materially from production, cache provenance is unknown, or source/byte selection cannot be observed. Unsupported tooling or network failures are not evidence that the control passed.

## Expected Findings

- Source restrictions cover top-level packages but omit a transitive dependency.
- A cold restore rejects a wrong-source fixture while a shared writable cache bypasses the intended boundary.
- CI updates the lock file during restoration instead of enforcing the reviewed graph.
- A custom native download accepts changed bytes despite a locked package-manager graph.
- An approved feed outage stops restoration without selecting the alternate fixture: expected secure behavior.

## Remediation Guidance

- Enforce source routing, approved dependency changes, and integrity checks in release automation.
- Pin supported tool versions and validate effective configuration across developer and CI environments.
- Separate less-trusted build caches from release caches and restrict writers.
- Protect lock files and hash manifests through review; a hash supplied by the same untrusted source is not independent provenance.
- Constrain auxiliary downloads and build scripts, and keep production secrets out of untrusted jobs.
- Preserve fixture-based regression tests without publishing collision packages.

## References

- [Microsoft: Package Source Mapping](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)
- [Microsoft: PackageReference and locking dependencies](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files)
- [Microsoft: dotnet restore](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-restore)
- [npm: npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci/)
- [npm: scopes and registries](https://docs.npmjs.com/cli/v11/using-npm/scope/)
- [npm: configuration and authentication scoping](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/)
- [Microsoft: vcpkg package version control](https://learn.microsoft.com/en-us/vcpkg/consume/lock-package-versions)
