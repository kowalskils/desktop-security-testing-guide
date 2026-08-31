# Sensitive Data in Binaries and Application Resources

| Field | Value |
| --- | --- |
| Test Case ID | DA3-T02 |
| Primary OWASP Category | DA3 - Sensitive Data Exposure |
| Secondary Categories | DA4 - Improper Cryptography Usage; DA8 - Poor Code Quality |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test determines whether a Windows desktop application's distributed artifacts expose sensitive data or security-relevant implementation details that should not be available to an untrusted local user. It examines installers, installed files, executables, DLLs, resources, managed assemblies, Electron archives, configuration, symbols, source maps, and other release artifacts.

In-scope data includes:

- Passwords, API secrets, private keys, reusable tokens, and signing material
- Database, cloud, messaging, or administrative credentials
- Cryptographic keys, static initialization values, and shared secrets
- Internal endpoints, hostnames, paths, usernames, and environment names
- Debug symbols, source paths, source maps, comments, and test data
- Disabled feature flags, hidden administrative functions, and non-production configuration
- Personal, financial, healthcare, or other regulated data embedded in samples or resources

Desktop artifacts can normally be copied, inspected, and reverse engineered by their users. Code signing, packing, and obfuscation may support integrity or raise analysis cost, but they do not make an embedded secret safe.

## Objective

Determine whether:

- Release artifacts contain hardcoded or embedded sensitive values.
- Resources expose credentials, keys, tokens, regulated data, or unsafe configuration.
- Debug, test, development, source, or build artifacts are included unintentionally.
- Managed code, Electron source, native strings, and metadata reveal reusable security material.
- The installer and installed application contain different or unexpected files.
- Sensitive values are shared across installations, tenants, users, or environments.
- Exposed information provides a credible unauthorized-access path.
- Build and release controls prevent recurrence and detect unintended artifact changes.

## Threat Model

The test considers attackers who can obtain a legitimate installer, copy installed application files, or access a user-readable application directory. The attacker is assumed to have ordinary static-analysis capabilities and does not need source-code access.

Potential impacts include unauthorized service access, compromise of installations sharing the same secret, decryption or forgery, discovery of internal infrastructure, privilege escalation through hidden functionality, exposure of regulated information, and acceleration of further attacks.

The presence of a URL, identifier, certificate, public key, product name, or ordinary string is not automatically a vulnerability. Findings must distinguish public configuration and non-secret metadata from confidential, privileged, or reusable material.

## Prerequisites and Safety

- Obtain the exact release artifact through an approved distribution channel.
- Confirm authorization to extract, disassemble, decompile, and inspect the application and its third-party components.
- Review applicable license, contractual, privacy, and data-handling requirements.
- Record the version, installer type, architecture, source, signer, and SHA-256 hash.
- Analyze in an isolated environment and preserve an untouched original package.
- Do not execute unknown extracted files merely because they came from a trusted installer.
- Do not upload proprietary artifacts, hashes, strings, or suspected secrets to public services without explicit authorization.
- Treat discovered credentials and private data as sensitive evidence immediately.

## Tools

1. **Sigcheck and PowerShell**
   - Record hashes, version metadata, manifests, Authenticode status, signers, and certificate chains.

2. **Sysinternals Strings**
   - Extract ANSI and Unicode strings for initial triage.

3. **PE inspection tools**
   - Review headers, imports, exports, resources, manifests, debug directories, signatures, and architecture.

4. **ILDasm and approved .NET analysis tools**
   - Inspect Common Intermediate Language, metadata, attributes, references, resources, and configuration.

5. **Electron ASAR tooling**
   - List or extract `app.asar` and inspect `app.asar.unpacked`, source maps, JavaScript, and preload scripts.

6. **Archive and installer tools**
   - Extract supported MSI, MSIX, ZIP, self-extracting, and vendor-specific packages.

7. **Local secret-detection tools**
   - Locate candidate credentials, key material, tokens, and connection strings. Results require manual validation.

No single tool identifies every embedded value. Combine inventory, string triage, format-aware inspection, and contextual validation.

## Testing Methodology

### Step 1 - Establish the Release Baseline

1. Record the artifact's filename, size, source, release channel, and acquisition time.
2. Calculate its SHA-256 hash:

```powershell
Get-FileHash -Algorithm SHA256 ".\ApplicationInstaller.exe"
```

3. Record its Authenticode status and signer:

```powershell
Get-AuthenticodeSignature ".\ApplicationInstaller.exe" |
    Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

4. Collect extended metadata with Sigcheck:

```powershell
sigcheck.exe -accepteula -a -h -i -m ".\ApplicationInstaller.exe"
```

5. Confirm that the artifact corresponds to the supported release under assessment.

Do not use Sigcheck options that query or upload to VirusTotal unless external disclosure is explicitly approved.

### Step 2 - Extract and Inventory the Package

1. Preserve the original package as read-only evidence.
2. Extract the package using a format-aware tool when authorized and feasible.
3. Install the application normally in an isolated environment.
4. Inventory the extracted package, installed directories, per-user directories, updater caches, and temporary installation locations.
5. Record path, size, extension, hash, version, signer, and source package for relevant files.
6. Compare extracted and installed inventories to identify generated, transformed, downloaded, or omitted artifacts.

```powershell
Get-ChildItem "C:\Program Files\Vendor\Application" -Recurse -File |
    ForEach-Object {
        [PSCustomObject]@{
            Path = $_.FullName
            Length = $_.Length
            SHA256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash
            FileVersion = $_.VersionInfo.FileVersion
        }
    } | Export-Csv ".\installed-file-inventory.csv" -NoTypeInformation
```

### Step 3 - Classify Artifacts

Group files by analysis path:

- Native PE files: `.exe`, `.dll`, `.sys`, `.ocx`, `.cpl`
- Managed assemblies and .NET metadata
- Electron `app.asar`, `app.asar.unpacked`, JavaScript, HTML, CSS, and native modules
- Configuration: `.config`, `.json`, `.xml`, `.yaml`, `.yml`, `.ini`, `.properties`, `.env`
- Resources, images, documents, templates, localization files, and embedded archives
- Debug and source artifacts: `.pdb`, `.map`, `.dbg`, source maps, source files, build logs, and test reports
- Key material: `.pem`, `.key`, `.pfx`, `.p12`, `.cer`, `.der`, and keystores
- Databases, sample data, backups, crash dumps, logs, and temporary files

Do not rely only on extensions. Inspect file signatures and container structure when the type is ambiguous.

### Step 4 - Perform Broad String Triage

1. Search ANSI and Unicode strings in binaries, archives, configuration, and resources.
2. Retain filenames and offsets so candidates can be traced to source artifacts.
3. Search for credential labels, private-key headers, connection strings, internal hosts, source paths, debug flags, test accounts, and non-production environments.
4. Decode serialized or encoded configuration only when its representation is identified through legitimate context. Encoding is not encryption.

```powershell
strings.exe -n 6 -o ".\Application.exe" > ".\Application.strings.txt"
strings.exe -u -n 6 -o ".\Application.exe" > ".\Application.unicode-strings.txt"

Select-String -Path ".\Application*.txt" -Pattern `
    "password", "secret", "token", "apikey", "connectionstring", `
    "BEGIN PRIVATE KEY", "jdbc:", "Server=", "Data Source="
```

Matches are leads, not confirmed findings. A field named `clientSecret` may contain a placeholder, test data, or a real secret.

### Step 5 - Inspect Native PE Files and Resources

For each first-party executable and DLL:

1. Record architecture, metadata, imports, exports, sections, and security-relevant headers.
2. Inspect resources for string tables, dialogs, manifests, version data, embedded files, certificates, templates, and configuration.
3. Review the debug directory for PDB paths, source references, build directories, and development metadata.
4. Inspect manifests for execution level, compatibility, and assembly references.
5. Identify appended overlays or nested archives that normal resource views may miss.
6. Correlate suspicious strings with their section or resource.

A PDB path or internal hostname is usually an information-disclosure lead. It becomes more significant when it reveals secrets, privileged infrastructure, sensitive identities, or demonstrably useful attack information.

### Step 6 - Inspect .NET Assemblies and Resources

1. Record assembly identity, target framework, references, and attributes.
2. Inspect IL and metadata with ILDasm or an approved tool:

```powershell
ildasm.exe ".\ManagedApplication.exe" /text /out=".\ManagedApplication.il"
```

3. Review string literals, static fields, configuration defaults, embedded resources, generated clients, and authentication, cryptographic, licensing, update, or administrative code.
4. Inspect adjacent `.config`, `.deps.json`, `.runtimeconfig.json`, and application-specific files.
5. Determine whether obfuscation changes only readability or whether a value remains recoverable through deterministic decoding or runtime use.

Do not report lack of obfuscation as proof of sensitive-data exposure. The security issue is the exposed data or control, not the readability of client code.

### Step 7 - Inspect Electron Artifacts

1. Locate `resources\app`, `resources\app.asar`, and `resources\app.asar.unpacked`.
2. List the ASAR before extraction:

```powershell
npx asar list ".\resources\app.asar"
```

3. When approved, extract it:

```powershell
npx asar extract ".\resources\app.asar" ".\analysis\app-asar"
```

4. Inspect `package.json`, main-process code, preload scripts, renderer code, IPC handlers, source maps, build-time variables, authentication and update configuration, service credentials, native modules, and unpacked files.
5. Check whether values exist in both source and generated assets.

ASAR is a packaging format, not a confidentiality boundary. Because `npx` may acquire and execute a package, use a pre-approved pinned tool from a trusted source in controlled environments.

### Step 8 - Inspect Configuration and Release Artifacts

Review for:

- Credentials copied from development, staging, or production
- Default administrative credentials or bypass values
- Private keys, key stores accompanied by passwords, or shared symmetric keys
- Sensitive sample records, databases, exports, backups, and fixtures
- Build-agent names, developer identities, repositories, source locations, and CI/CD paths
- Source maps, PDBs, test reports, coverage data, and build logs
- Updater URLs, signing configuration, and release-channel switches

Public certificates and public keys are not secrets. Establish whether private material is present and whether the application incorrectly treats a distributed shared value as confidential.

### Step 9 - Validate Candidate Secrets

1. Record file, hash, offset or resource, representation, and context.
2. Classify the value as public, non-sensitive, sensitive pending validation, or a confirmed secret/private record.
3. Determine whether it is complete, current, environment-specific, and shared.
4. Identify the related system, account, tenant, or cryptographic operation.
5. When explicitly authorized, validate with the least invasive method:
   - Prefer metadata or a harmless read-only operation.
   - Use only approved test accounts and environments.
   - Do not enumerate unrelated data or modify state.
   - Stop after establishing acceptance, rejection, or cryptographic relevance.
6. If validation is not authorized, report uncertainty without claiming access.

Never place a discovered secret in a URL, command history, screenshot, ticket title, or filename. Redact it and retain a short fingerprint or hash for correlation.

### Step 10 - Compare Installations and Releases

1. Compare suspected values across clean installations, users, machines, architectures, and channels.
2. Determine whether a supposedly unique value is global or deterministic.
3. Check whether removed secrets remain in old binaries, backups, updater caches, or previous-version directories.
4. Confirm whether remediation revokes or rotates the value rather than merely hiding the current copy.

### Step 11 - Protect Evidence

1. Preserve original hashes and tool versions.
2. Store extracted files and output in an access-controlled evidence directory.
3. Retain enough context to reproduce the match without copying the complete secret into the report.
4. Follow approved retention and disposal procedures.

## Evidence to Collect

- Original package source, version, signer, and SHA-256 hash
- Extracted and installed inventories with paths, sizes, hashes, versions, and signatures
- Artifact classification and tool versions
- String evidence with filename, encoding, offset, pattern, and context
- PE resource, manifest, debug-directory, and embedded-file evidence
- .NET IL, metadata, resource, and configuration evidence
- Electron ASAR inventory and unpacked-resource evidence
- Candidate classification, fingerprint, apparent scope, and validation status
- Cross-installation or cross-release comparison when performed
- Attacker prerequisites, demonstrated impact, uncertainty, and evidence-disposal record

## Pass/Fail Criteria

### Pass

The test passes when distributed artifacts contain no reusable confidential credentials, private keys, protected records, or other values that should remain outside the client trust boundary; production packages exclude unintended debug, test, source, and environment material; and exposed implementation details do not create a credible unauthorized-access path.

### Fail

The test fails when:

- A reusable password, token, API secret, private key, shared key, or privileged connection string is embedded in a distributed artifact.
- A supposedly per-user, per-machine, or per-installation secret is static or predictably derived.
- A release contains real personal, financial, healthcare, production, or other protected data.
- Development artifacts expose a credential, privileged endpoint, bypass, or sensitive source material with demonstrated impact.
- Old binaries, caches, or backups retain an exposed secret.
- Obfuscation or reversible encoding is the primary protection for a client-distributed secret.

Severity should reflect reusability, privilege, scope, environment, rotation capability, affected installations, attacker prerequisites, and impact.

### Needs Further Investigation

Use this outcome when completeness, validity, ownership, environment, or intended confidentiality cannot be established. Internal paths, hostnames, public identifiers, certificates, and feature names remain unconfirmed until credible impact is demonstrated.

## Expected Findings

### Secure or Expected Conditions

- Artifacts contain only public identifiers and configuration intended for distribution.
- Authentication uses user-specific or short-lived material obtained at runtime.
- Private keys and privileged service credentials remain in controlled server-side or platform-protected stores.
- Production packages exclude unnecessary symbols, source maps, source, test data, logs, backups, and non-production configuration.
- Installer and installed inventories are understood and reproducible.

### Potential Findings

- Cloud, database, messaging, telemetry, or administrative credentials are embedded.
- Private or shared encryption keys appear in a PE resource, managed resource, ASAR, or adjacent file.
- PDBs or source maps expose source, infrastructure, or security-relevant comments.
- Test accounts, bypass flags, hidden privileged functions, or development endpoints remain in production.
- Real customer or employee data is shipped as a sample, fixture, database, or document.
- The same supposedly unique material appears in every installation.

## Remediation Guidance

- Assume all client code and resources can be inspected by an untrusted user.
- Keep privileged credentials, signing keys, and master secrets outside desktop artifacts.
- Use scoped, short-lived credentials provisioned through authenticated runtime flows.
- Protect local secrets with an appropriate platform mechanism and threat-model-driven key strategy; encoding and obfuscation are not key management.
- Remove unnecessary symbols, source maps, source, logs, test data, backups, and non-production configuration.
- Separate public client identifiers from confidential service credentials in build systems.
- Add secret scanning and artifact-content checks to the release pipeline with reviewed allowlists.
- Maintain an expected-file manifest so unexpected contents fail the release.
- On exposure, remove, rotate or revoke, investigate historical releases, and assess use.
- Retest the final packaged installer rather than only source or intermediate build output.

## References

- [OWASP Desktop Application Security Top 10: DA3](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft: Portable Executable format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft Sysinternals: Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)
- [Microsoft Sysinternals: Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
- [Microsoft .NET: View assembly contents with ILDasm](https://learn.microsoft.com/en-us/dotnet/standard/assembly/view-contents)
- [Microsoft .NET Framework: ILDasm](https://learn.microsoft.com/en-us/dotnet/framework/tools/ildasm-exe-il-disassembler)
- [Electron: ASAR archives](https://www.electronjs.org/docs/latest/tutorial/asar-archives)
- [Electron: Application packaging](https://www.electronjs.org/docs/latest/tutorial/application-distribution)
