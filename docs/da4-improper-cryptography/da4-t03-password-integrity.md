# Password-Based Protection, Hashing, and Integrity Controls

| Field | Value |
| --- | --- |
| Test Case ID | DA4-T03 |
| Primary OWASP Category | DA4 - Improper Cryptography Usage |
| Secondary Categories | DA2 - Broken Authentication and Session Management; DA3 - Sensitive Data Exposure; DA8 - Poor Code Quality |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope

This test validates password verifiers, password-derived encryption keys, hashes, MACs, signatures, checksums, license/update integrity, local database protection, and migration of stored cryptographic formats.

## Objective and Threat Model

Determine whether passwords use salted, costed, purpose-appropriate derivation; salts are unique; optional peppers are separately protected; integrity decisions use MACs or signatures rather than unkeyed hashes; comparison and errors resist practical oracle behavior; and stored formats can be upgraded. Attackers may steal verifier databases, modify files or metadata, substitute updates, compare installations, or perform offline guessing.

## Prerequisites and Tools

- Use synthetic passwords with controlled duplicates across users and installations.
- Record format, algorithm, salt, cost, output length, pepper/key location, version, and upgrade path.
- Use approved static/runtime analysis, format parsers, timing measurements, and offline test hardware only within authorized limits.

## Testing Methodology

### Step 1 - Inventory Password and Integrity Operations

Map login verifiers, vault/database unlock, exports, recovery, licensing, configuration integrity, plug-ins, IPC messages, installers, updates, and signatures. Identify whether each requirement is confidentiality, password verification, corruption detection, authenticity, or non-repudiation.

### Step 2 - Validate Password Verifiers

Create users with the same synthetic password and compare stored records. Each must have a unique random salt. Identify the KDF and cost; test whether the cost is encoded, bounded, and upgradeable. Fast general-purpose hashes, reversible encryption, unsalted hashes, PBKDF1, and direct password use are failures for password verification.

### Step 3 - Validate Password-Derived Encryption

Compare identical plaintext protected with the same password across repetitions and installations. Validate independent random salt, adequate KDF work factor, distinct encryption and authentication keys, authenticated ciphertext, and explicit format versioning. Determine whether password change safely rewraps or rederives protection without data loss or silent fallback.

### Step 4 - Validate Pepper and Recovery Design

If a pepper or recovery secret exists, confirm it is not stored with the verifier database, shipped in the client, logged, or shared beyond its intended boundary. Test authorized recovery, rotation, compromise response, and the inability of recovery metadata to bypass authentication.

### Step 5 - Validate Integrity Controls

Modify protected files, configuration, manifests, updates, plug-ins, license data, and security metadata. Unkeyed hashes and CRCs can detect accidental corruption but do not establish authenticity against an attacker who can replace data and hash. Validate MAC or digital-signature verification, trusted key selection, metadata binding, certificate/key lifetime, and fail-closed behavior before use.

### Step 6 - Validate Comparison and Error Handling

Confirm full MAC/tag/signature verification uses approved APIs and does not accept truncation unless explicitly designed. Compare invalid password, corrupted data, wrong key, invalid tag, and unsupported version behavior for information leakage, excessive timing differences, or fallback.

### Step 7 - Validate Migration and Resource Limits

Open legacy synthetic records and verify successful authentication upgrades them to the current format. Reject attacker-selected excessive cost, allocation, or length parameters that could cause denial of service. Verify rollback does not restore weak verifiers or integrity policy.

## Evidence to Collect

Operation inventory; stored-format samples using synthetic data; algorithm, salt, cost, pepper/key, version, and output length; duplicate-password comparison; tamper matrix; error/timing observations; migration and rollback results; and offline-attack assumptions. Never include real passwords or peppers.

## Pass/Fail Criteria

### Pass

Password values use a salted, costed, upgradeable password KDF; encryption derived from passwords uses authenticated, purpose-separated keys; integrity decisions use an appropriately keyed MAC or trusted digital signature; failures occur before use; and legacy formats migrate safely.

### Fail

Fail for plaintext/reversible password storage, unsalted or fast hashes, obsolete KDFs, static salts, client-embedded peppers, reused derived keys, unauthenticated password encryption, unkeyed hashes used as authenticity controls, ignored/truncated verification, insecure fallback, or non-upgradeable weak formats.

### Needs Further Investigation

Use when the stored format, effective cost, pepper location, trust anchor, verification reachability, attacker write capability, or migration behavior cannot be established.

## Remediation Guidance

- Use an approved password KDF with unique random salts and a calibrated work factor; version the stored format.
- Use platform one-shot KDF APIs where available and replace PBKDF1 or direct hashes.
- Protect peppers outside client artifacts and verifier databases.
- Derive separate purpose-bound keys and use authenticated encryption.
- Use HMAC for shared-secret integrity and trusted digital signatures for distributable authenticity.
- Authenticate algorithm/version/key metadata, bound resource parameters, fail closed, and migrate weak records after successful verification.

## References

- [Microsoft: .NET cryptography model](https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
- [Microsoft CA5373: Do not use obsolete key derivation](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5373)
- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations)
- [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
