# V2 test results

Baseline portable suite: 11 passed, 0 failed. Prior V1 hosted run 41171713736: 14 unique automated tests passed on source 43ec5d9, not physical hardware.

Current passive foundation checkpoint: **27 portable XCTest tests passed, 0 failed** on Linux Swift 6.0.2, plus CLI valid/archive rejection checks. App source syntax parsing passed, but hosted Xcode validation of these new changes is still pending. Track run https://github.com/onlykappa/omnisign-ios/actions/runs/41172825357 on source b9b1a55.

New regression coverage: corrupt/empty index metadata fails without overwrite; missing local IPA refuses restore; streaming copy rejects actual-byte overflow and cleans staging; expiration is checked at use; malformed profile identifiers/wildcards are rejected; journal completes only a persisted inspection; restart marks interrupted stage and does not replay; all mutation/auth kinds stay blocked; invalid transitions/missing persisted package cannot succeed; corrupt history is preserved; diagnostic schema excludes free-form secrets and rejects tampered messages; update decisions reject missing/mismatched identity and unsigned/unprovisioned evidence; group/data/downgrade cautions; numeric version comparison; backend-specific -80045/-80046/7460 handling; auth/security/429 stop policy; persisted distinct retry-policy budget.

These are actual core tests and pure-policy tests, not simulated Apple/device successes. Existing hosted app integration test was extended to require a Completed inspection journal record and secret-free export. Existing Keychain/UI tests are retained. No real certificate/private-key/CMS/signature, pairing service, transport interruption, refresh schedule, real installation or owner-app data test has run.

An initial test-source compilation issue (`await` inside XCTest autoclosure) was corrected before the 27-test passing checkpoint. No runtime failure was hidden. Live HTTP/provider/hardware tests remain absent. A Linux ZIPFoundation privacy-manifest resource warning persists as in V1. No target iOS 27.0.1 result exists.

See ROADMAP.md for open gates. Current overall classification: **V2 Blocked by V1 signing/transport/hardware prerequisites**, with passive foundation implementation tested only as described above. Hardware absence is not the only blocker: the required mutation backends are missing.
