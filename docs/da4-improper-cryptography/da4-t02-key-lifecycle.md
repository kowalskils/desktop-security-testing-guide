# Cryptographic Key Lifecycle and Protection

| Field | Value |
| --- | --- |
| Test Case ID | DA4-T02 |
| Primary OWASP Category | DA4 - Improper Cryptography Usage |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test validates generation, provisioning, storage, access, scope, use, rotation, revocation, backup, recovery, migration, and destruction of symmetric keys, private keys, key-encryption keys, signing keys, and high-value application secrets.

## Objective and Threat Model

Determine whether keys are unpredictable, unique at the required boundary, accessible only to intended identities, separated by purpose, replaceable, recoverable only through approved workflows, and destroyed when no longer authorized. Attackers may inspect artifacts or memory, run as another user, copy protected blobs between systems, tamper with key identifiers, or obtain backups and old releases.

## Prerequisites and Tools

- Use synthetic data and keys on two Windows users and, when relevant, two machines.
- Inventory CNG key stores, certificate stores, DPAPI blobs, Credential Manager references, files, Registry values, configuration, environment variables, services, Electron stores, and remote KMS/HSM integrations.
- Use Process Monitor, ACL tools, certificate utilities, approved debuggers, and application instrumentation without exporting production private keys.

## Testing Methodology

### Step 1 - Build a Key Inventory

For every key, record owner, purpose, algorithm, size, generator, identifier, storage, protection layer, user/machine/tenant scope, allowed operations, consumers, creation, cryptoperiod, rotation, backup, recovery, revocation, destruction, and protected data dependencies.

### Step 2 - Trace Generation and Provisioning

Confirm keys use a platform CSPRNG or approved key service. Compare clean installations, users, tenants, clones, and restored images to detect static, deterministic, or reused material. Verify provisioning authenticates the destination identity and does not expose keys in command lines, logs, installers, configuration, or temporary files.

### Step 3 - Validate Storage and Access

Inspect effective ACLs and cryptographic access policies. Test access as the intended user, another standard user, service identities, and administrator only where the threat model claims isolation. Establish whether the application stores plaintext keys, embeds keys in binaries, or places a wrapping key beside ciphertext with equivalent access.

### Step 4 - Validate DPAPI and Platform Scope

For controlled blobs, identify user versus machine scope, optional entropy location, profile/credential dependency, and recovery behavior. Test same user, second user, second machine, password change, administrator reset, roaming, profile restore, and supported migration. Machine scope must not be mistaken for per-user isolation.

### Step 5 - Validate Separation and Use

Confirm distinct keys or derived subkeys for encryption, authentication, signing, wrapping, tenants, environments, and materially different purposes. Test whether a key identifier, purpose, tenant, or version can be modified to make the application use the wrong key.

### Step 6 - Validate Rotation and Revocation

Rotate a synthetic active key through the supported workflow. Verify new writes use the new key, authorized old data remains readable only as required, rollback cannot reactivate revoked creation keys, caches update, failures are recoverable, and audit records identify the operation without exposing material.

### Step 7 - Validate Backup, Recovery, and Destruction

Inspect backups and recovery packages for confidentiality, integrity, authorization, separation of duties, and retention. Remove an account or revoke a key and verify active stores, caches, memory, logs, old versions, and backups follow the documented destruction or retention policy.

## Evidence to Collect

Key inventory; generation/provider evidence; cross-installation comparison; paths and ACLs; DPAPI scope matrix; purpose/tenant separation; rotation and rollback results; recovery authorization; destruction/retention results; and attacker prerequisites. Fingerprint keys with hashes rather than placing raw key material in reports.

## Pass/Fail Criteria

### Pass

Keys are unpredictable, appropriately scoped, least-privilege protected, purpose-separated, versioned, rotatable, recoverable under controlled authorization, and destroyed or retained according to policy without exposure.

### Fail

Fail when keys are embedded or plaintext, reused across an unintended boundary, accessible to unintended identities, protected by colocated material, incorrectly machine-scoped, interchangeable across purposes or tenants, non-rotatable, recoverable without authorization, or retained after required destruction.

### Needs Further Investigation

Use when key identity, scope, provider, exportability, effective access, rotation dependency, or recovery ownership cannot be established.

## Remediation Guidance

- Generate keys through CNG, .NET cryptographic APIs, or an approved managed key service.
- Prefer non-exportable platform keys or opaque handles where architecture permits.
- Select DPAPI scope deliberately and document same-user and administrator limitations.
- Separate keys by purpose, environment, tenant, and privilege; authenticate key metadata.
- Define cryptoperiods, versioned formats, rotation, revocation, recovery, and destruction procedures.
- Keep recovery keys and backups under stronger, separately authorized controls.

## References

- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations)
- [Microsoft: CryptProtectData and DPAPI scope](https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptprotectdata)
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST SP 800-133 Rev. 2](https://csrc.nist.gov/pubs/sp/800/133/r2/final)
