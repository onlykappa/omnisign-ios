# V2 release readiness

**V2 Blocked**: required V1 signing, authorized installation transport, account/provisioning backends and physical-device acceptance are absent. Passive reliability source/tests exist; this is not a complete implementation merely awaiting hardware. No fundamental stock-iOS impossibility is proven, but the essential dependency/provisioning path has not been satisfied.

| Gate | Result |
|---|---|
| V1 source/history/Phase 0 audit | Complete with explicit unresolved critical blockers |
| Safe foundation regressions and passive policies | Implemented; 47 portable + 9 native app + 1 UI tests passed at latest hosted checkpoint |
| Hosted Xcode/Simulator validation | Run41201716117 source2bf03b6 passed Simulator tests, unsigned iPhone build/package and own IPA inspection |
| Real Apple signing/provisioning and independent signatures | Missing/blocked |
| Paired service install/refresh/update verification | Missing/blocked |
| Physical iPhone 17/iOS 27.0.1, zero-PC and saved-data tests | Not run |
| Complete security/license audit | Incomplete; no unlicensed signer linked |
| Owner approval to merge/release | Not given; both PRs must remain draft/unmerged |

Use V2 Functional only after actual target-device signing/install/refresh/safe update acceptance passes. Use V2 Experimental only when required implementation and automated suites are complete but hardware acceptance remains. At present neither condition applies.

PR #2 is a queued stacked draft against PR #1, not a production upgrade on main. V1 must be made functional and left unmerged before expanding V2 mutation automation. Progress is in ROADMAP.md and ../WORK_STATE.md. Do not equate a passing build, zero command exit, inspection Completed state or Compatible policy result with a successful iPhone installation.

Synthetic isolated signing output passed native Mac structural/cryptographic checks in run41201328417; it does not establish an Apple development identity/profile or phone installability. Source1a39bfd adds locally tested disposable key generation; hosted dual-origin/Apple-anchor rejection and iOS compilation passed run41203139779. Inspection preview is ready for owner Windows bootstrap, while the actual sign/install/refresh acceptance gate remains blocked.

PFX integrity/key selection hardening passed14 lab tests plus dual-origin cryptographic/native/iOS-compile checks in run41203535444. Disposable saved-value fixture1.0/1.1 built in run41203656751. Both advance verification preparation; neither closes any physical acceptance gate.
