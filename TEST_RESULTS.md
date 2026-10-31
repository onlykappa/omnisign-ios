# Test results

Classification: **V1 Experimental**, not a functional release. Phase 0 gate remains closed. Test date: 2026-10-31 UTC.

## Executed

Environment: Debian 13 Linux x86_64. Swift 6.0.2 RELEASE, language mode Swift 5. ZIPFoundation exact 0.9.20, revision locked in Package.resolved. The toolchain was downloaded from download.swift.org into scratch; no Apple SDK was installed.

`swift test`: **11 XCTest tests passed, 0 failed**. These tests exercise the actual OmniCore implementation:

- IPA metadata and nested framework/extension/dylib inventory; deterministic children-first plan.
- Rejection of traversal, absolute/backslash paths, Unicode/case canonical collisions policy, symlinks, CRC corruption, multiple root apps, missing executable, unsupported magic, missing framework metadata and oversized declared entries. Unicode normalization is implemented; the fixture collision is ASCII case, not a separate Unicode fixture.
- Atomic normal import, index reload, failed-import cleanup and preservation of prior records.
- Decoded provisioning-plist parsing, expiration rejection, team and bundle identifier compatibility. No CMS authenticity test.
- Conservative exact-string entitlement policy. No real binary entitlement extraction or reconciliation test.
- Incompatible bundle IDs and unverified-signature installation preflight refusal.
- Every disabled engine operation refuses to succeed.
- Five-distinct-strategy recovery cap, duplicate refusal, auth/security/503 stop policy.
- Diagnostic schema allowlisting and known-code originating-stage preservation; HTTP 503 classification.
- Invalid/incomplete pairing-schema rejection. No real pairing-secret fixture.

`omnisign-inspect` was compiled and executed against the synthetic valid IPA: exit 0, correct version 1.2/build 2, three bundles, one dylib, seven entries, 857 expanded bytes. Traversal fixture: exit 1, `unsafeArchive`. These are disposable archive fixtures, not runnable signed apps.

`swiftc -frontend -parse App/OmniSignApp.swift App/SecureStore.swift`: passed syntax parsing. This does **not** resolve SwiftUI/Security modules, type-check iOS APIs, generate an app, or establish runtime behavior.

`scripts/test.sh` regenerates fixtures, runs XCTest and checks CLI acceptance/rejection. Raw redacted console evidence is in docs/automated-tests.log. The separate Swift Testing runner reports zero tests because the suite uses XCTest; it is not an additional acceptance suite.

## Setup failures resolved

The first Swift download URL returned 404; the documented ubuntu2204 Swift 6.0.2 path succeeded. The toolchain expected an unavailable gold linker; a scratch wrapper named ld.gold invokes the bundled ld.lld. This changes no repository source or system binaries. ZIPFoundation 0.9.19 failed on this Linux toolchain's optional FILE pointer API; upgrading the exact dependency to 0.9.20 resolved it. A test-source dictionary `keys()` typo was corrected before the final passing suite. Final runs have no failed tests. A ZIPFoundation Linux warning about an unhandled privacy-manifest resource remains; iOS resource inclusion requires Xcode verification.

## Initial local snapshot limitations (superseded by hosted results below where stated)

| Requirement | Result |
|---|---|
| XcodeGen generation, Xcode iOS build, simulator, signed/installable IPA | Unavailable: no macOS/Xcode/iOS SDK |
| SwiftUI layout, Liquid Glass rendering, Keychain/file-protection/URLSession integration | Not validated on iOS |
| Development certificate/private-key ownership/Apple trust | Backend incomplete; not tested |
| CMS profile authenticity and actual typed binary entitlements | Not implemented/tested |
| Recursive cryptographic signing and independent signature verification | Not implemented/tested; planning test is not signing |
| Authorized Apple authentication/provisioning | Not attempted; no account credentials requested |
| Pairing compatibility and VPN/device-service connection | Not attempted; no phone or pairing credentials |
| Installation, launch, refresh and in-place update | Not attempted; disabled |
| Saved-data survival | Unknown; no app was installed/updated |
| iPhone 17 / iOS 27.0.1 | No physical device evidence |
| Owner Kodi/KappaForge | Not touched; no actual IPAs tested |

Automated success applies only to the portable core and CLI. Full archive fuzzing, malformed Mach-O load commands, signatures, certificate validation, install recovery and OS integration need additional suites after the missing backends exist. Follow docs/DEVICE_ACCEPTANCE.md; do not relabel the build Functional until its physical checks run.

## Hosted Xcode validation — completed

Successful run: https://github.com/onlykappa/omnisign-ios/actions/runs/41171713736 . Tested source commit: `43ec5d90128f45faca347bd5be45d3023a3bec72`. Public standard `macos-15` runner; Xcode 16.4 (16F6), Swift 6.1.2, iPhoneOS/iPhoneSimulator build SDK 18.5. The installed Simulator runtime selected by simctl was **iPhone 17 Pro Max / iOS 26.2**, which is distinct from the requested physical iPhone 17 / iOS 27.0.1. No target-device acceptance is implied.

Results:

- 11 portable XCTest cases passed on the hosted Mac; CLI valid/hostile archive checks passed.
- XcodeGen project generation and Swift package resolution passed.
- Simulator application compilation passed.
- Two hosted iOS application integration tests passed: actual IPA import through AppModel with persisted reload; Keychain save/update with synthetic data and invalid certificate rejection. Protected library initialization succeeded; this does not test locked-device file-protection enforcement.
- One UI automation test passed: launch and navigation through all five sections, with screenshots attached to the xcresult evidence.
- Unsigned arm64 iPhone Release build passed.
- Unsigned IPA packaging and artifact upload passed. Artifact: https://github.com/onlykappa/omnisign-ios/actions/runs/41171713736/artifacts/13031625597 . Artifacts are retained for seven days, not published as a release.

**14 unique automated tests passed** across portable and iOS suites; zero failed in this successful run. An earlier full run, https://github.com/onlykappa/omnisign-ios/actions/runs/41171253345 , failed its Keychain test when Simulator code signing was disabled. The corrective run uses local ad-hoc Simulator signing (`CODE_SIGN_IDENTITY=-`), requiring no Apple account, while the iPhone artifact remains unsigned. Numeric Keychain error codes are now retained without secret-bearing backend strings; certificate inspection disables network trust fetching. The earlier failure remains visible rather than being omitted.

Unsigned IPA SHA-256 reported by the successful runner:

```text
749ffc77248fed6022343f166751e9ddccc65ce603ff9c7f7fdaed8d1942befa
```

The CLI artifact-download route returned HTTP 403 at its blob redirect in this execution environment. The GitHub connector successfully returned the artifact as a downloadable file reference. No local rehash or local inspection of that hosted IPA is claimed. The SHA above is the runner's recorded output; Windows users should independently compare their downloaded copy per docs/WINDOWS_BOOTSTRAP.md.

Remaining unverified: iOS 27.0.1 and physical-device behavior, Files/iCloud provider interaction, HTTPS downloads in iOS, hardware file-protection enforcement, real certificate/private-key eligibility, CMS profile trust, real entitlements/signatures, account/provisioning backend, pairing compatibility, authorized device transport, signing/install/launch/refresh/update and saved-data preservation. Signing/install/refresh remain disabled. **Classification remains V1 Experimental.**
