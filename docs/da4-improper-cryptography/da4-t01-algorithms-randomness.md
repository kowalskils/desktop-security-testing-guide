# Cryptographic Algorithms, Modes, Parameters, and Randomness

| Field | Value |
| --- | --- |
| Test Case ID | DA4-T01 |
| Primary OWASP Category | DA4 - Improper Cryptography Usage |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA8 - Poor Code Quality |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test validates cryptographic primitives used by a Windows desktop application for confidentiality, integrity, signatures, key derivation, identifiers, tokens, and protocol support. It covers algorithm choice, mode, key length, IV or nonce construction, tag length, padding, randomness, parameter reuse, error handling, and migration behavior.

## Objective

Determine whether the application uses approved, purpose-appropriate primitives; avoids obsolete algorithms and custom cryptography; generates unpredictable keys and security tokens; preserves nonce and IV requirements; authenticates ciphertext; and supports safe algorithm and parameter migration.

## Threat Model

An attacker may obtain ciphertext, influence plaintext, modify stored data, compare multiple installations, trigger repeated operations, observe errors, or predict values produced by weak randomness. Impact includes plaintext recovery, forgery, token prediction, signature bypass, and compromise across installations.

## Prerequisites and Safety

- Use synthetic plaintext, keys, accounts, and records in an isolated lab.
- Record application version, platform, provider, configuration, and test workflow.
- Obtain authorization before tampering with ciphertext or invoking hidden diagnostic functions.
- Preserve original artifacts and never upload proprietary cryptographic material to public services.

## Tools

- Static analysis and approved decompilers for identifying APIs, constants, and custom implementations
- Process Monitor and debugging tools for runtime provider and data-flow confirmation
- CNG, PowerShell, .NET, and format-aware test utilities for controlled verification
- Statistical output can support investigation but does not prove a generator is cryptographically secure

## Testing Methodology

### Step 1 - Build a Cryptographic Inventory

For every operation, record purpose, input, output format, algorithm, provider, mode, key length, IV or nonce, tag or MAC, padding, hash, randomness source, key identifier, failure behavior, and applicable data lifetime. Include native libraries, .NET, JavaScript, WebCrypto, Electron modules, database encryption, licensing, update verification, and third-party SDKs.

### Step 2 - Identify Implementations

Search binaries, assemblies, configuration, imports, and runtime activity for CNG/CAPI, `System.Security.Cryptography`, WebCrypto, OpenSSL, bundled libraries, algorithm names, fixed byte arrays, seeds, IVs, nonces, and home-grown transforms. Confirm suspected dead code through runtime or build evidence before reporting it as active.

### Step 3 - Validate Algorithm and Key Strength

Compare active algorithms and parameters with current organizational and platform guidance. Flag active DES, 3DES/TDEA, RC4, ECB, MD5 or SHA-1 for security decisions, undersized keys, unauthenticated custom encryption, and proprietary ciphers unless a narrowly documented compatibility exception is effective.

### Step 4 - Validate IV and Nonce Behavior

1. Encrypt identical synthetic plaintext repeatedly under the same key.
2. Compare complete output and extracted IV or nonce fields.
3. Repeat across restart, reinstall, another user, and another machine.
4. Determine whether uniqueness or unpredictability required by the selected mode is maintained.
5. For AES-GCM or CCM, establish that a nonce is never reused with the same key and that authentication tags are verified before plaintext is consumed.

### Step 5 - Validate Integrity and Tamper Handling

Modify ciphertext, IV or nonce, tag, associated data, version, and metadata one field at a time. The application must reject the object without exposing unauthenticated plaintext, revealing an oracle through distinguishable errors, or falling back to a weaker format. If CBC is required, validate Encrypt-then-MAC with separate keys.

### Step 6 - Validate Randomness

Identify the generator used for keys, tokens, reset codes, nonces, salts, challenges, and identifiers. Native code should use an approved system CSPRNG such as `BCryptGenRandom`; .NET should use `RandomNumberGenerator`. Demonstrate whether values repeat or become predictable across rapid calls, restart, clock changes, process IDs, users, and machines. `rand`, `System.Random`, timestamps, counters, GUID structure, and non-cryptographic PowerShell randomness are not suitable sources for secrets.

### Step 7 - Validate Parameter and Format Binding

Confirm that algorithm, version, key identifier, purpose, tenant, and relevant metadata are authenticated rather than attacker-selectable. Test downgrade to legacy formats and cross-purpose use of a ciphertext, signature, or MAC.

### Step 8 - Document Results

Retain the operation inventory, code/runtime evidence, controlled inputs and outputs, nonce comparison, tamper matrix, randomness source, downgrade result, provider/version, and attacker prerequisites.

## Pass/Fail Criteria

### Pass

The test passes when approved primitives and adequate parameters are used for their intended purpose, randomness comes from a CSPRNG, IV/nonce requirements hold, ciphertext integrity is verified before use, downgrade is controlled, and algorithms can be migrated without silently weakening protection.

### Fail

The test fails when active protection relies on obsolete or custom cryptography, ECB, predictable security values, reused nonce/key pairs, constant or predictable IVs where prohibited, unauthenticated encryption, ignored tags, oracle-like errors, or attacker-controlled downgrade.

### Needs Further Investigation

Use this result when an algorithm is present but active reachability, provider behavior, key/nonce relationship, compatibility constraint, or protected security property cannot be established.

## Remediation Guidance

- Prefer platform-supported libraries and authenticated encryption such as AES-GCM where its nonce requirements can be guaranteed.
- Use AES with appropriate key sizes and a CSPRNG for keys, IVs, nonces, tokens, salts, and challenges.
- Authenticate ciphertext and security-relevant metadata; separate encryption and MAC keys when AEAD is unavailable.
- Remove obsolete and custom primitives, version formats, enforce downgrade policy, and define crypto-agility and migration tests.
- Fail closed with uniform externally visible errors and never consume unauthenticated plaintext.

## References

- [OWASP Desktop Application Security Top 10: DA4](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations)
- [Microsoft: .NET cryptography model](https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
- [Microsoft: BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
