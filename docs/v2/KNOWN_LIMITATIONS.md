# V2 known limitations

- V1 is not complete. Apple authentication, certificate/private-key intelligence, CMS profile acquisition/verification, binary entitlement reconciliation, real signing/independent signature validation and installation/refresh backends remain missing.
- Target physical iPhone 17/iOS 27.0.1 has never been connected or tested. Free-only independent transport provisioning is unresolved. Hosted build/runtime evidence is different.
- V2 journal executes only real inspection bookkeeping. Other operation kinds are permanently blocked; no retries, reconnects, background tasks or scheduling execute. Attempt number is one for these inspection records. Typed retry budget is an unused pure policy, not an autonomous task engine.
- Update policy trusts caller-supplied evidence for policy evaluation only. It cannot discover inventory or prove data preservation, and cannot authorize/execute installation. Versions outside dotted ASCII numbers are Unknown.
- Pairing/certificate imports and memory-only errors do not yet have complete persistent lifecycle history. Inspection history is bounded to 256 records/2 MiB; oldest terminal history can be pruned. There is no automatic deletion of IPAs or installed apps.
- Library/index and journal are separate atomic documents, not a shared transaction. A crash or journal write failure after a real archive commit can preserve an unreported import; restart may show the imported IPA and an Interrupted record. Never infer installation from either.
- Corrupt index/history fails closed without replacing bytes. No automatic corrupt-state repair, tamper-proof storage, deduplication or crash-orphan cleanup is implemented. Library writes require the single app coordinator.
- Mach-O checks remain shallow until separately upgraded. Archive caps and rejection of all symlinks may exclude legitimate large Kodi layouts.
- Real provider/HTTP interruption and locked-device protection tests are absent. Diagnostic export contains generated operation/app UUIDs and timing, not bundle IDs/teams/source URLs/secrets.
- No rollback package strategy, update history from installed services, owner-app migration, expiration notifications or polished V2 UI. Functional gates take precedence over cosmetics.
- No production, zero-PC or self-refresh claim. No merge/release has been authorized or performed.
