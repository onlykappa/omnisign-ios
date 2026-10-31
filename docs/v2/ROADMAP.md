# V2 roadmap — queued behind V1

Owner policy: keep PR #1 and PR #2 draft and unmerged. PR #2 is stacked on `feat/v1-experimental`, not main. V1 functional acceptance must precede V2 signing/install automation. No automatic merge, deployment, publication or release. Target: physical iPhone 17 / iOS 27.0.1. Free-only and on-device first.

- [x] Read V1 source, documentation, Phase 0, history and draft PR #1.
- [x] Re-run existing portable suite; confirm prior hosted evidence separately.
- [x] Audit core capabilities and explicitly record missing signer/transport/hardware blockers.
- [ ] Fix corrupt-index validation, bounded import copy and expiration-at-use policies with regression tests.
- [ ] Preserve HTTP provenance and safe numeric error context.
- [ ] Implement inspection-only persistent operation records with restart/interruption reporting; no signing/install execution.
- [ ] Add conservative Compatible/Caution/Blocked update policy; keep actual update actions disabled.
- [ ] Run portable regression tests and hosted iOS integration/UI builds; save evidence.
- [ ] Resolve all V1 signer/transport license and implementation prerequisites in PR #1 or reviewed follow-up commits.
- [ ] Demonstrate V1 sign/install/launch/refresh/update/data survival on the actual target, with computer disconnected.
- [ ] Only after that gate: implement V2 certificate intelligence, authenticated account/session lifecycle, exact profile/entitlement reconciliation and independent signature verification.
- [ ] Implement authorized transport discovery/reconnect, verified installation and opportunistic refresh/reminders.
- [ ] Integrate evidence-backed Kodi/KappaForge update decisions/history and rollback guidance.
- [ ] Add failure-aware recovery with at most five evidence-distinct suitable attempts; no auth/security/destructive retries.
- [ ] Complete security review, missing automated suites and V2 physical acceptance.
- [ ] Obtain owner approval before any merge/release; do not infer approval from completion.

No simulated or command-exit-only success can satisfy a device/signature gate. Completion checkboxes must link evidence or identify the test. Future work and actual implementation must be distinguished in every report. See ../WORK_STATE.md for resume instructions.
