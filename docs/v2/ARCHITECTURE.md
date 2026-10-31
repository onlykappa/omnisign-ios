# V2 architecture

Status: blocked behind V1 signing/device prerequisites; passive foundation code exists. PR #2 is stacked on unmerged PR #1. No mutation automation is enabled.

Implemented modules:

- `BoundedFile`: byte-counted reads and streaming copies; staged output is removed on failure.
- `Inspection`/`Library`: restore-time metadata validation, regular local-package checks, bounded index and atomic index persistence. One app coordinator serializes imports; multiple independent Library writers are unsupported.
- `OperationJournal`: actor-isolated JSON document, atomic writes, 2 MiB/256-record bounds, UUID app references, stages/timestamps/attempt/result/allowlisted diagnostics. Only real inspections may reach Completed, after persisted library evidence is reloaded. Signing/auth/install/update/refresh begin as Blocked and cannot transition to success. On restart, running inspections become Interrupted and retain their prior stage; nothing resumes automatically. Oldest terminal history can be pruned at retention bound; no IPA or installed application is deleted.
- `FailureAssessment`/`EvidenceRetryBudget`: pure source-aware policy, bounded typed strategies, no network/device calls or scheduler. Apple auth/certificate/provisioning and security restrictions stop automation. The active app never invokes these strategies.
- `SafeUpdatePolicy`: pure Compatible/Caution/Blocked decision with missing-evidence, identity, signature/profile/entitlement, group/data/downgrade reasons. Caller assertions are not independent evidence, and a policy result never enables installation.
- `AppModel`: real inspection operation records, persistent interrupted-history display, explicit owner-triggered redacted export; downloads stream off the UI actor. Pairing/certificate imports still do not have complete persistent lifecycle records.

Future gated pipeline: inspect → actual architecture/entitlements/CMS verification → authorize account/session → reuse private-key-backed identity → exact profiles → sign nested code → independent signature/resource validation → authorized service handshake → bounded transfer/install → service inventory/profile proof → foreground launch/data acceptance. Each stage needs its own evidence and regression suite. UI progress must reflect real stage boundaries; no artificial percentages.

Secrets remain outside the journal. Personal identifiers, app bundle IDs, URLs, session material, certificates, private keys and pairing data are not accepted as journal messages. Journal timestamps and generated UUIDs are local operation metadata, not credentials. A damaged history/index fails closed and preserves bytes instead of resetting or manufacturing success.
