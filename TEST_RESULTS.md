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

## Not executed / not passed

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
