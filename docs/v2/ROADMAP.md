# V2 roadmap — queued behind V1

Owner policy: keep PR #1 and PR #2 draft and unmerged. PR #2 is stacked on `feat/v1-experimental`, not main. V1 functional acceptance must precede V2 signing/install automation. No automatic merge, deployment, publication or release. Target: physical iPhone 17 / iOS 27.0.1. Free-only and on-device first.

- [x] Read V1 source, documentation, Phase 0, history and draft PR #1.
- [x] Re-run existing portable suite; confirm prior hosted evidence separately.
- [x] Audit core capabilities and explicitly record missing signer/transport/hardware blockers.
- [x] Fix corrupt-index validation, bounded import copy and expiration-at-use policies with regression tests.
- [x] Preserve HTTP provenance and safe numeric error context.
- [x] Implement inspection-only persistent operation records with restart/interruption reporting; no signing/install execution.
- [x] Add conservative Compatible/Caution/Blocked update policy; keep actual update actions disabled.
- [x] Pass hosted inspection-history/certificate checkpoint (34 tests, run 41173560308) and V1 foundation backport (18 tests, run 41174314865).
- [x] Implement bounded DER certificate metadata and CMS profile inspection with no trust grant; 42 portable tests pass with current structural regressions.
- [x] Implement bounded thin/fat/load-command/encryption/XML-entitlement inspection and additional native inventory; cryptographic/DER/device validity remains unverified.
- [x] Implement explicit read-only local identity discovery/key challenge source; no app signing activation.
- [x] Verify identity/native/profile and later pairing/runtime source on hosted iOS; run41201716117 passed57 unique tests (47 core9 app1 UI). Earlier Swift6.1 fixture type-check failures are retained in TEST_RESULTS.md.
- [x] Run isolated pinned AGPL synthetic signing experiment: run41201328417 passed primitives/tamper checks and Mac native structural/cryptographic verification. No Apple development authorization or iPhone installability. Gate remains closed.
- [x] Implement read-only accessible-key proof, offline Apple-root candidate analysis, source-traced pairing schemas/replacement approval and passive runtime/network diagnostics; hosted tests passed.
- [x] Add local Swift-only disposable identity factory and reject silently ignored PFX encryption; 8 local lab tests plus independent OpenSSL identity checks passed.
- [x] Pass source1a39bfd hosted run41203139779: Apple-anchor rejection, both synthetic origins and isolated signer/support iOS cross-compile.
- [x] Harden isolated PFX integrity/key selection with14 local/hosted tests and dual-origin signing checks (source4a32f5f/run41203535444); full production audit remains open.
- [x] Build disposable saved-value SwiftUI fixture1.0/1.1 with exact metadata checks (sourced5632a9/run41203656751); physical data-preservation test NOT RUN.
- [ ] Complete production signer/transitive audit and full independent signature trust validation; do not weaken verifier to make a test pass.
- [ ] Resolve all V1 signer/transport license and implementation prerequisites in PR #1 or reviewed follow-up commits.
- [ ] Demonstrate V1 sign/install/launch/refresh/update/data survival on the actual target, with computer disconnected.
- [ ] Only after that gate: implement V2 certificate intelligence, authenticated account/session lifecycle, exact profile/entitlement reconciliation and independent signature verification.
- [ ] Implement authorized transport discovery/reconnect, verified installation and opportunistic refresh/reminders.
- [ ] Integrate evidence-backed Kodi/KappaForge update decisions/history and rollback guidance.
- [ ] Add failure-aware recovery with at most five evidence-distinct suitable attempts; no auth/security/destructive retries.
- [ ] Complete security review, missing automated suites and V2 physical acceptance.
- [ ] Obtain owner approval before any merge/release; do not infer approval from completion.

No simulated or command-exit-only success can satisfy a device/signature gate. Completion checkboxes must link evidence or identify the test. Future work and actual implementation must be distinguished in every report. See ../WORK_STATE.md for resume instructions.

- [x] Add independent bounded Swift code-page/special-slot/CMS verification;18 lab tests and dual-origin Mac/iOS-compile checks passed (a342feb/run41204139145, strict rerun41204233854). This is not full resource/trust/device verification.
- [x] Make required app/lab CI stages fail on each error/pipeline; YAML/bash checked, V1 local15 tests passed, hosted lab strict rerun passed.
- [ ] Resolve Library UI failure41203656725; inspect explicit-selection/hierarchy follow-up41204383402 and strict app/V1 runs41204233846/41204248419.
- [ ] Preserve checkpoint and resync V2 ancestry onto updated V1 after pending diagnostics; leave both drafts unmerged.
