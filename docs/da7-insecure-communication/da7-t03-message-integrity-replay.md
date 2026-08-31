# Message Integrity, Replay, and Session Binding

| Field | Value |
| --- | --- |
| Test Case ID | DA7-T03 |
| Primary OWASP Category | DA7 - Insecure Communication |
| Secondary Categories | DA2 - Broken Authentication; DA4 - Improper Cryptography Usage; DA5 - Improper Authorization |

## Scope and Objective

This test validates application-message authenticity, freshness, ordering, session/user/tenant binding, endpoint authorization, duplicate handling, and secure use of WebSocket, MQTT, database, queue, custom TCP/UDP, and offline synchronization protocols. TLS protects a connection; it does not automatically make captured application messages non-replayable or correctly authorized.

## Methodology

1. Inventory message types, senders, receivers, brokers, topics, queues, databases, sequence fields, timestamps, nonces, signatures/MACs, acknowledgments, retry stores, and authorization decisions.
2. Capture only synthetic authorized messages and document session, user, tenant, device, connection, destination, and expected side effect.
3. Replay unchanged messages in the same connection, a new connection, after logout/timeout, as another user/tenant/device, and after server restart.
4. Modify object IDs, tenant/user fields, destination/topic, ordering, timestamp, nonce, flags, and duplicated or omitted messages one field at a time.
5. Test delayed, reordered, concurrent, fragmented, duplicated, and offline-queued delivery without load-based denial of service.
6. Verify messages are bound to the authenticated channel/session and authorized object; client-supplied identity must not override server context.
7. For brokers and databases, validate authentication, topic/schema permissions, wildcard subscriptions, retained messages, management interfaces, and transport protection.
8. Confirm retry and idempotency controls prevent duplicate privileged or financial effects while permitting safe recovery.

## Evidence and Criteria

Collect protocol/message inventory, synthetic captures, session context, modified/replayed inputs, server responses, side effects, authorization records, broker permissions, and freshness/idempotency evidence.

Pass when messages are authenticated where required, fresh, context-bound, object-authorized, correctly ordered or safely idempotent, and rejected after session invalidation. Fail for accepted replay causing unauthorized/duplicate effects, cross-user or cross-tenant substitution, unauthenticated messages, writable privileged topics, insecure retained data, or trust in client identity/timestamps alone. Use `Needs Further Investigation` when side effect, server context, broker policy, freshness state, or authorization owner is unknown.

## Remediation Guidance

Bind messages to authenticated sessions, users, tenants, operations, destinations, and protocol versions; use nonces/sequence windows and bounded timestamps; authenticate security-relevant fields; authorize objects server-side; implement idempotency keys and transactional duplicate handling; secure broker topics and retained messages; and invalidate queued/replay state on logout or revocation.

## References

- [OWASP Desktop Application Security Top 10: DA7](https://owasp.org/www-project-desktop-app-security-top-10/)
- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations)
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
