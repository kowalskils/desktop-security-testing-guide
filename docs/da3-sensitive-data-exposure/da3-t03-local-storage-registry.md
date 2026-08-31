# Sensitive Data in Local Storage and the Windows Registry

| Field | Value |
| --- | --- |
| Test Case ID | DA3-T03 |
| Primary OWASP Category | DA3 - Sensitive Data Exposure |
| Secondary Categories | DA4 - Improper Cryptography Usage; DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test determines whether a Windows desktop application stores sensitive data securely in files, databases, caches, temporary locations, and the Windows Registry. It also verifies whether permissions, encryption, key scope, cleanup behavior, and tamper resistance match the application's threat model.

In-scope locations include:

- `%LOCALAPPDATA%`, `%APPDATA%`, `%PROGRAMDATA%`, `%TEMP%`, `%PUBLIC%`, and the user profile
- Application installation, update, backup, export, recovery, and crash-reporting directories
- Documents, downloads, recent-file data, clipboard-related artifacts, and application-defined paths
- SQLite, ESE, LevelDB, JSON, XML, YAML, INI, configuration, log, and cache files
- Electron `Local Storage`, IndexedDB, Cookies, Session Storage, and Chromium profile data
- `HKCU`, `HKLM`, and the 32-bit and 64-bit Registry views
- Credentials, tokens, keys, connection strings, personal records, document content, and security settings

The presence of data in a user-profile directory is not automatically secure or insecure. The result depends on the data's sensitivity, authorized users, effective ACLs, encryption, key scope, device threat model, retention period, and whether a less-privileged identity can read or modify it.

## Objective

Determine whether:

- Sensitive values are stored in plaintext or another directly reusable form.
- Files and Registry keys are readable or writable by unintended users or processes.
- Encryption keys are stored beside the encrypted data or shared across installations.
- DPAPI or another protection mechanism uses an appropriate user or machine scope.
- Logout, account removal, cache clearing, and uninstall remove data according to policy.
- Backups, journals, temporary files, crash artifacts, and previous versions retain sensitive data.
- Security-relevant configuration can be modified to bypass controls or elevate privilege.
- Multiple application users or Windows users can access one another's data.

## Threat Model

The test considers:

- Another standard user on a shared Windows system
- Malware or a compromised process running as the same user
- A local attacker with access to user-writable directories or Registry keys
- An attacker who obtains a disk image, profile backup, roaming profile, support bundle, or application export
- An attacker who tampers with local security settings, databases, tokens, or update state
- An administrator or offline attacker when the product claims protection against those actors

Potential impacts include credential theft, session replay, disclosure of regulated data, cross-user exposure, security-control bypass, privilege escalation, unauthorized configuration changes, and recovery of supposedly deleted information.

Encryption does not replace authorization. DPAPI protects data under a Windows identity or machine context, but data can still be exposed to a process running as that identity, through key-scope mistakes, or after legitimate decryption by the application.

## Prerequisites and Safety

- Use an isolated Windows test environment with a restorable snapshot.
- Create at least two non-administrative Windows test users when cross-user behavior is relevant.
- Use synthetic application accounts and distinctive synthetic data markers.
- Record the application, installer, Windows, architecture, and test-user details.
- Capture a filesystem and Registry baseline before installation or first launch.
- Obtain authorization before changing ACLs, Registry values, databases, tokens, or configuration.
- Back up test artifacts before controlled tampering and restore them afterward.
- Do not copy real profiles, production databases, credentials, or customer data into the lab.
- Protect collected files and Registry exports as sensitive evidence.

## Test Data Design

Use unique markers for each data type, Windows user, application user, and workflow. Examples:

| Purpose | Example Marker |
| --- | --- |
| User A record | `DSTG-STORAGE-USERA-71C9` |
| User B record | `DSTG-STORAGE-USERB-28E4` |
| Synthetic token | `DSTG-TOKEN-LOCAL-63A2-SYNTHETIC` |
| Sensitive document | `DSTG-DOCUMENT-LOCAL-94F1` |
| Security setting | `DSTG-SETTING-TAMPER-52B8` |

Use new markers for repeated tests so stale data can be attributed to a specific run.

## Tools

1. **Process Monitor**
   - Discovers file and Registry activity during installation, authentication, sensitive workflows, logout, update, and uninstall.

2. **Process Explorer**
   - Correlates activity with process identity, integrity level, and child processes.

3. **PowerShell**
   - Inventories files, hashes, ACLs, Registry values, and before-and-after state.

4. **`icacls` and AccessChk**
   - Review effective access and inherited permissions for files, directories, processes, services, and Registry locations.

5. **Registry Editor and Registry command-line tools**
   - Inspect values, types, views, virtualization, and key permissions.

6. **Format-aware viewers**
   - Inspect SQLite, ESE, LevelDB, JSON, XML, and other application formats without modifying original evidence.

7. **Approved DPAPI test tooling or application instrumentation**
   - Determines protection scope and whether controlled blobs decrypt under another user or machine context.

Tool output must be correlated with a controlled workflow and effective security boundary.

## Testing Methodology

### Step 1 - Establish the Baseline

1. Snapshot the test system before installation or first launch.
2. Record existing vendor and product paths under common per-user and machine-wide locations.
3. Record existing product-related Registry keys in `HKCU` and `HKLM`.
4. Start Process Monitor with filters for the installer and application processes.
5. Record process names, users, integrity levels, and architecture.

Do not assume a fixed path. Windows known folders can be redirected, and packaged applications may use private application locations.

### Step 2 - Discover Filesystem and Registry Writes

Exercise these states separately:

1. Installation and first launch
2. Application authentication
3. Creation or opening of sensitive data
4. Preference and security-setting changes
5. Logout, account switch, and timeout
6. Update and rollback
7. Cache clearing and account removal
8. Uninstall, including any option to retain user data

In Process Monitor, filter by target process names and review operations including:

- `CreateFile`, `WriteFile`, `SetEndOfFile`, `SetRenameInformationFile`, and `SetDispositionInformationFile`
- `RegCreateKey`, `RegSetValue`, `RegDeleteValue`, and `RegDeleteKey`

Record paths, value names, processes, users, timestamps, and outcomes. Include helper, renderer, updater, service, and crash-handler processes.

### Step 3 - Inventory Discovered Artifacts

For each relevant file, record:

- Full path, owner, size, timestamps, hash, and effective ACL
- File format and whether it is active data, cache, journal, backup, export, log, or temporary content
- Windows and application user associated with the artifact
- Creation, update, and deletion workflow

Example:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Vendor\Application" -Recurse -Force -File |
    ForEach-Object {
        [PSCustomObject]@{
            Path = $_.FullName
            Length = $_.Length
            SHA256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash
            Owner = (Get-Acl $_.FullName).Owner
        }
    } | Export-Csv ".\local-storage-inventory.csv" -NoTypeInformation
```

For each Registry location, record hive, full key path, value name, type, data classification, owner, inheritance, and effective access. Inspect both 32-bit and 64-bit views when applicable.

### Step 4 - Search for Controlled Sensitive Data

1. Search discovered files, databases, Registry values, logs, caches, backups, and temporary content for exact markers.
2. Search plaintext, Unicode, and application-identified serialized representations.
3. Inspect database auxiliary files such as SQLite WAL and journal files.
4. Inspect prior versions, renamed files, autosave data, and export packages.
5. Record every copy and the application state in which it was created.

Do not classify an encoded or compressed value as encrypted without identifying a cryptographic protection mechanism and its key handling.

### Step 5 - Inspect Native and .NET Storage

Review:

- Application `.config` files and user-scoped configuration
- JSON, XML, INI, binary serialization, isolated storage, and local databases
- Credential Manager or platform credential references
- DPAPI-protected blobs and the code path that protects and unprotects them
- Connection strings, remembered-user data, recent documents, and authentication caches
- Service and machine-wide configuration under `%PROGRAMDATA%` and `HKLM`

Determine whether protection is bound to the intended Windows user, machine, application account, or enterprise identity.

### Step 6 - Inspect Electron and Chromium Storage

Map the application's profile directory and inspect:

- `Local Storage` and LevelDB files
- IndexedDB and Session Storage
- Cookies and network state
- Cache, code cache, GPU cache, and service-worker storage
- Preferences, Local State, logs, crash reports, and updater data
- Custom stores used by application frameworks or plug-ins

Verify whether logout clears application-layer tokens and records from every relevant renderer and profile store. Chromium storage formats or encrypted cookie values do not establish that custom application tokens are protected correctly.

### Step 7 - Evaluate File and Directory ACLs

1. Inspect permissions on each directory in the path, not only the final file.
2. Identify inherited and explicit ACEs for standard users, `Users`, `Authenticated Users`, `Everyone`, service identities, and application-specific groups.
3. Check read, write, create, delete, rename, change-permission, and ownership rights according to the threat model.
4. Verify effective access using a second standard Windows user.

```powershell
icacls "C:\ProgramData\Vendor\Application"
Get-Acl "C:\ProgramData\Vendor\Application" | Format-List
```

A per-user file readable by its owning Windows user may be expected. A machine-wide credential or privileged configuration writable by all standard users is normally not.

### Step 8 - Evaluate Registry Permissions and Views

1. Review security descriptors on product keys under `HKCU` and `HKLM`.
2. Test read and write access as the intended standard-user identities.
3. Inspect parent-key inheritance and newly created subkeys.
4. Review both native and alternate Registry views for 32-bit and 64-bit applications.
5. Determine whether Registry virtualization changes the observed path or security context.
6. Identify security settings, service paths, executable paths, update channels, plug-in locations, and command-line arguments stored in writable keys.

```powershell
Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\Application" |
    Format-List Owner, AccessToString
```

### Step 9 - Validate DPAPI and Key Scope

For each protected value:

1. Confirm that it is actually protected rather than encoded or compressed.
2. Identify whether protection is scoped to the current user or local machine.
3. Determine where optional entropy or other key material is stored.
4. Using only synthetic values, test whether the blob can be decrypted:
   - By the same application user and Windows user
   - By another standard Windows user on the same machine
   - On another clean test machine
5. Test the application's supported migration, roaming, backup, password-change, and recovery scenarios.

Machine-scoped DPAPI permits decryption in the machine context and may be unsuitable for data that must be isolated between users. User-scoped DPAPI does not prevent same-user malware or the authorized application from obtaining plaintext.

Do not extract real DPAPI master keys or use credential-recovery techniques unless that activity is explicitly authorized and necessary for the threat model.

### Step 10 - Validate Tamper Resistance Safely

Select a synthetic security-relevant value, such as a role cache, server endpoint, update channel, feature restriction, executable path, or certificate-validation flag.

1. Preserve the original file or Registry value and its permissions.
2. Attempt modification as the relevant lower-privileged test user.
3. Launch the application through its normal workflow.
4. Observe whether the change is rejected, ignored, detected, restored, or trusted.
5. Stop once security impact is established; do not invoke privileged or destructive functionality.
6. Restore the original value and verify normal operation.

Writable configuration is not automatically a vulnerability. It becomes a finding when the application trusts it across a security boundary or it exposes sensitive data to an unauthorized identity.

### Step 11 - Validate Cleanup and Retention

1. Capture an artifact inventory before and after logout, timeout, account removal, cache clearing, and uninstall.
2. Search for the unique markers after each transition.
3. Inspect backups, journals, temporary files, previous versions, updater caches, crash reports, and exported support bundles.
4. Verify whether a second application user or Windows user can recover the first user's data.
5. Compare observed retention with product documentation and organizational policy.

Deletion from the active database does not prove that data is absent from journals, backups, unallocated storage, or synchronized copies. Report only recovery paths demonstrated within scope.

### Step 12 - Document and Protect Evidence

1. Preserve hashes and read-only copies of relevant artifacts before analysis.
2. Redact secrets and personal data from screenshots and reports.
3. Record exact identities, ACLs, state transitions, and commands required to reproduce the result.
4. Restore controlled changes.
5. Dispose of collected profiles, Registry exports, databases, and decrypted synthetic material according to the approved procedure.

## Evidence to Collect

- Application, installer, Windows, architecture, and test-user details
- Process Monitor capture and workflow timestamps
- File and Registry inventories before and after each state transition
- File hashes, formats, owners, inheritance, and effective ACLs
- Registry hives, views, key paths, values, owners, and access rights
- Marker matches with file, database, Registry, cache, backup, or log context
- DPAPI or encryption scheme, scope, key location, and controlled portability results
- Cross-user read/write results and controlled tamper outcomes
- Logout, timeout, account-removal, cache-clear, and uninstall retention results
- Cleanup and evidence-disposal record

## Pass/Fail Criteria

### Pass

The test passes when sensitive data is stored only where required, protected according to its threat model, isolated from unintended users, and removed according to defined lifecycle events. Security-relevant files and Registry values have appropriate effective permissions, encryption keys are managed separately from ciphertext, and controlled tampering cannot cross a security boundary.

### Fail

The test fails when:

- A credential, token, private key, regulated record, or equivalent sensitive value is stored in directly reusable plaintext without a justified control.
- An unintended Windows or application user can read another user's sensitive data.
- A standard user can modify machine-wide or privileged configuration that the application trusts across a security boundary.
- Encrypted data and its reusable key or password are stored together with equivalent access.
- A shared or incorrectly scoped DPAPI design permits unintended cross-user access.
- Sensitive data remains recoverable after a lifecycle event that promises or requires removal.
- Backups, logs, journals, exports, crash artifacts, or temporary files bypass the protection applied to active storage.

Severity should reflect data sensitivity, validity, affected identities, ACL prerequisites, cryptographic scope, tamper impact, retention, and attacker access.

### Needs Further Investigation

Use this outcome when data is present but its sensitivity, protection, ownership, retention requirement, decryption scope, or effective attacker access cannot be established. Do not report encryption based only on unreadable file contents.

## Expected Findings

### Secure or Expected Conditions

- Per-user data is isolated by correct ACLs and application authorization.
- High-value secrets use an appropriate platform protection mechanism and scope.
- Machine-wide directories and Registry configuration are not writable by unintended standard users.
- Logout, timeout, account removal, and cache clearing remove or invalidate relevant sensitive state.
- Temporary, backup, journal, export, and crash artifacts receive equivalent protection.
- Uninstall behavior matches the documented retention choice.

### Potential Findings

- Tokens, credentials, keys, connection strings, or personal records appear in plaintext files or Registry values.
- Electron stores authentication data in readable LevelDB or JSON content after logout.
- SQLite WAL or backup files retain records removed from the active database.
- `%PROGRAMDATA%`, installation, updater, or Registry locations grant broad write access.
- Machine-scoped protection exposes user-specific secrets to other local contexts.
- Security settings can be altered by editing a user-writable file or Registry value.
- A second user can recover the first user's cached documents or session data.

## Remediation Guidance

- Minimize local collection and retention of sensitive data.
- Use Windows known-folder APIs rather than hardcoded paths and select per-user or machine-wide storage deliberately.
- Apply least-privilege ACLs to every directory and Registry key in the trust path.
- Use an appropriate credential store or DPAPI scope for locally required secrets, with a documented recovery and roaming model.
- Keep encryption keys separate from ciphertext and avoid application-wide static secrets.
- Authenticate security-relevant configuration or enforce it in a more trusted process or server-side control.
- Clear authentication state across all processes and stores during logout, timeout, revocation, and account switch.
- Protect backups, logs, journals, temporary files, crash reports, exports, and support bundles to the same standard as active data.
- Define and test retention behavior for cache clearing, account removal, updates, rollback, and uninstall.
- Add automated tests for ACL baselines, secret scanning, cross-user isolation, and lifecycle cleanup.

## References

- [OWASP Desktop Application Security Top 10: DA3](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft: Windows known folder identifiers](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)
- [Microsoft: CryptProtectData example and DPAPI scope](https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptprotectdata)
- [Microsoft: CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [Microsoft: Registry key security and access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
- [Microsoft: Registry Provider for PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_registry_provider)
- [Microsoft: icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [Microsoft Sysinternals: Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Microsoft Sysinternals: AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
