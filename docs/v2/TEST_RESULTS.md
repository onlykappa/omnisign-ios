# V2 test results

Baseline portable suite: 11 passed, 0 failed. Prior V1 hosted run 41171713736: 14 unique automated tests passed on source 43ec5d9, not physical hardware.

Current passive foundation checkpoint: **27 portable XCTest tests passed, 0 failed** on Linux Swift 6.0.2, plus CLI valid/archive rejection checks. App source syntax parsing passed, but hosted Xcode validation of these new changes is still pending. Track run https://github.com/onlykappa/omnisign-ios/actions/runs/41172825357 on source b9b1a55.

New regression coverage: corrupt/empty index metadata fails without overwrite; missing local IPA refuses restore; streaming copy rejects actual-byte overflow and cleans staging; expiration is checked at use; malformed profile identifiers/wildcards are rejected; journal completes only a persisted inspection; restart marks interrupted stage and does not replay; all mutation/auth kinds stay blocked; invalid transitions/missing persisted package cannot succeed; corrupt history is preserved; diagnostic schema excludes free-form secrets and rejects tampered messages; update decisions reject missing/mismatched identity and unsigned/unprovisioned evidence; group/data/downgrade cautions; numeric version comparison; backend-specific -80045/-80046/7460 handling; auth/security/429 stop policy; persisted distinct retry-policy budget.

These are actual core tests and pure-policy tests, not simulated Apple/device successes. Existing hosted app integration test was extended to require a Completed inspection journal record and secret-free export. Existing Keychain/UI tests are retained. No real certificate/private-key/CMS/signature, pairing service, transport interruption, refresh schedule, real installation or owner-app data test has run.

An initial test-source compilation issue (`await` inside XCTest autoclosure) was corrected before the 27-test passing checkpoint. No runtime failure was hidden. Live HTTP/provider/hardware tests remain absent. A Linux ZIPFoundation privacy-manifest resource warning persists as in V1. No target iOS 27.0.1 result exists.

See ROADMAP.md for open gates. Current overall classification: **V2 Blocked by V1 signing/transport/hardware prerequisites**, with passive foundation implementation tested only as described above. Hardware absence is not the only blocker: the required mutation backends are missing.

## New inspection/certificate checkpoints

Local source 0ab2990: **42 portable tests passed, zero failed**, plus CLI checks. Native inspector regression tests cover thin/fat architectures, slice overlap, bounded load commands/signature ranges, encryption flags, typed/bounded untrusted XML entitlements and extra `.so`/extensionless native inventory. Certificate tests use a public synthetic DER certificate and verify exact date/OU parsing, expired/not-yet-valid policy, truncated/indefinite/trailing DER and invalid calendar-date rejection. CMS profile tests use a public non-Apple synthetic SignedData envelope, reject malformed/detached/trailing inputs, retain expired metadata for inspection and never grant CMS trust.

Hosted run https://github.com/onlykappa/omnisign-ios/actions/runs/41173560308 succeeded at source b56ee51 (before V2 rebase): **34 unique tests** (30 portable, 3 app integration, 1 UI), Xcode generation, Simulator/unsigned iPhone builds and packaging. This predates deeper Mach-O and identity-proof additions.

Newer runs 41173996191, 41174346622 and 41174515238 failed a Swift 6.1 type-check timeout in the long test-fixture `Data + Data` expression. Linux Swift 6.0.2 had passed it. The builder was simplified in 7650caf; **run 41174709903 remains pending/in progress at this checkpoint**, followed by profile source run 41175000886. Passing Linux tests are not substituted for hosted results. The new private-key test must verify a generated matching identity and reject an unrelated certificate, without checking any fixture secret into GitHub.

## Isolated signing experiment

Separate AGPL laboratory, not an app dependency: https://github.com/onlykappa/omnisign-ios/actions/runs/41173298634 and https://github.com/onlykappa/omnisign-ios/actions/runs/41174346608 succeeded. Four real clang-generated disposable Mach-O targets (app, framework, extension, dylib) were signed with an ephemeral self-signed RSA identity by pinned CodeSignKit. Independent Python/OpenSSL checks verified their code-page/special-slot hashes, listed resource hashes and detached CMS mathematics against that synthetic identity. Resource tampering was rejected.

**Apple's `codesign --verify --deep --strict` rejected the output (`nativeCodesignAccepted=false`).** No Apple development trust, target-device execution, provisioning, real signing identity, installation or zero-PC acceptance has been demonstrated. A green primitive experiment does not close the signing gate; its JSON records Apple authorization/installation/physical validation as false. No lab keys/P12/password/certificate/binary are uploaded; only sanitized build/verification evidence. Root app dependency graph is unchanged.

V1 backport also passed hosted run https://github.com/onlykappa/omnisign-ios/actions/runs/41174314865 on source 1f6d402: 18 unique automated tests (15 portable + 2 app + 1 UI). This fixes V1's index/copy/expiration regressions without merging PR #1.
