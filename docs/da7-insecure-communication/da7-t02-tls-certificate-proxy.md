# TLS, Certificate, Proxy, and Downgrade Validation

| Field | Value |
| --- | --- |
| Test Case ID | DA7-T02 |
| Primary OWASP Category | DA7 - Insecure Communication |
| Secondary Categories | DA4 - Improper Cryptography Usage; DA6 - Security Misconfiguration |

## Scope and Objective

This test validates TLS versions, cipher policy, certificate chain, hostname, validity, usage, revocation, client certificates, trust-store changes, proxy behavior, redirects, pinning where claimed, and downgrade/failure handling for every application endpoint.

## Methodology

1. Inventory the TLS stack and policy used by native, .NET, Electron, updater, telemetry, plug-in, database, and helper components.
2. Record negotiated protocol, cipher, certificate chain, name, validity, EKU, revocation behavior, SNI, ALPN, and client-auth requirements.
3. In an authorized interception lab, test an untrusted root, wrong hostname, expired/not-yet-valid/revoked certificate, incomplete chain, wrong EKU, self-signed leaf, and substituted client certificate.
4. Test system proxy, explicit proxy, PAC, environment proxy, authenticated proxy, redirect, and proxy failure. Confirm secrets are not sent to a new origin or proxy unexpectedly.
5. Disable or reject modern negotiation on the lab endpoint and confirm no fallback to obsolete TLS, plaintext, alternate insecure ports, or validation bypass.
6. Review custom callbacks and test flags; .NET callbacks that accept every certificate and equivalent native/Electron behavior are prohibited in production.
7. If pinning is claimed, test backup pins, rotation, expiry, failure mode, and administrative interception policy without creating an availability trap.

## Evidence and Criteria

Collect endpoint/component matrix, handshakes, chains, validation errors, proxy/redirect destinations, callback/configuration evidence, downgrade results, and user-visible behavior.

Pass when supported TLS and certificate validation fully authenticate the intended peer, errors terminate the connection, proxy/redirect boundaries preserve authorization, and downgrade is rejected. Fail for accept-any validation, hostname/chain/time/usage failure acceptance, insecure protocol fallback, secrets redirected cross-origin, or production debug bypass. Use `Needs Further Investigation` when platform policy, revocation availability, enterprise trust requirements, or actual component stack is unknown.

## Remediation Guidance

Use platform TLS defaults with TLS 1.3/1.2 policy; validate name, dates, chain, usage, and revocation; remove accept-all callbacks; constrain redirects and credential forwarding; separate test trust; design pin rotation; and fail closed without plaintext fallback.

## References

- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations)
- [Microsoft: DangerousAcceptAnyServerCertificateValidator](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.dangerousacceptanyservercertificatevalidator)
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
