# V1 gap audit

Baseline: a09269b, draft PR #1. Reviewed complete tracked source, scripts, XcodeGen/SwiftPM/workflow specifications, V1 Markdown, research lock and prior commits. Existing local 11-test suite re-run successfully; prior hosted run 41171713736 separately confirms 11 portable + 2 app + 1 UI tests and unsigned builds on source 43ec5d9. It used Xcode 16.4/SDK 18.5 and iPhone 17 Pro Max Simulator/iOS 26.2. No physical iPhone result exists.

## Capability inventory

| Capability | Classification | Actual evidence |
|---|---|---|
| IPA archive inspection/import/persistence | Verified through automated tests only | Portable and hosted import/reload tests; no complete binary/signature validation |
| Native navigation | Verified through automated tests only | Hosted five-section navigation test |
| Keychain generic-secret storage | Verified through automated tests only | Hosted synthetic save/update and invalid DER rejection |
| Certificate trust display | Implemented but unverified for valid development certificates | Basic X.509 Security call, no private-key proof/expiry/team inspection |
| Legacy pairing schema import | Implemented but unverified on physical hardware | Invalid schemas tested, no live handshake |
| Real Apple authentication/session/2FA/anisette | Missing | No account networking backend; never requested credentials |
| Certificate reuse/profile acquisition/CMS trust | Missing | Decoded-plist helper is not CMS trust or portal manager |
| Recursive signing/signature validation | Missing | `ExperimentalEngine.perform` always throws unavailable; inventory is not signing |
| Installation/refresh/update/launch evidence | Missing | No device-service implementation; actions disabled |
| Zero-PC transport and iOS 27.0.1 compatibility | Blocked | No entitled free-only transport demonstrated; no target hardware |
| Background autonomy | Blocked | Missing verified signer/refresh path; no guaranteed iOS execution |
| Kodi/KappaForge safe updates/data retention | Missing | No actual owner IPA/device tests; no deletion attempted |
| RecoveryBudget/preflight helpers | Experimental | Pure policy tests; no executing recovery engine |

No core capability is classified Verified on physical hardware. There are no mocked Apple responses or simulated installation successes. Disabled buttons, generic icons, Unknown statuses and the unavailable engine are explicit incomplete surfaces.

## Gap register

Each row lists source, reproduction, fix and required evidence. Status changes belong in the verification addendum after tests run.

| ID / severity | Affected source and reproduction | Proposed fix / test requirement | Baseline actual result |
|---|---|---|---|
| G01 Critical | `Safety.swift:ExperimentalEngine`; call sign/install/refresh | Audited licensed signer, independent signatures, exact profiles, physical disposable-app acceptance | Always unavailable, expected; unresolved blocker |
| G02 Critical | `App/OmniSignApp.swift` disabled actions; no device gateway exists | Licensed pairing/lockdown/Remote Pairing, transport/storage/service preflight, install completion and inventory/launch evidence | No handshake/installation; unresolved blocker |
| G03 Critical | `docs/PHASE0.md`, research lock; inspect SideSign license and free VPN entitlement assumptions | Confirm license grant or alternative, pin/audit transitives, demonstrate free-only transport distribution | No SideSign integration; unresolved blocker |
| G04 Critical | `COMPATIBILITY.md`; look for physical target logs | Execute target-device and zero-PC acceptance with disposable IPA | No actual iPhone 17/iOS 27.0.1 evidence; unresolved blocker |
| G05 High | `Library.load`, `Inspection.main`; decode index containing `bundles: []`, then access main | Validate restored metadata and referenced local package before returning; corruption must fail closed without overwriting index | Unchecked array indexing can crash; reproduction regression required |
| G06 High | `Library.importIPA`; source grows between size check and copy | Stream copy with actual byte bound and private staging cleanup; test bounded copy rejection and old-index preservation | FileManager.copyItem has no streaming cap |
| G07 High | `ProfileSummary.permits`; retain summary beyond expiration or use malformed wildcard/team | Check validity at use, validate identifier grammar and wildcard scope; deterministic clock tests | Expiration checked only at init |
| G08 High | `Inspection.checkMachO`; magic+zero padding is accepted | Comprehensive load-command/CPU/encryption/entitlement/CMS verification before enabling signing | Only shallow magic check; unresolved blocker, warnings already present |
| G09 Medium | `DiagnosticCategory.classify`, `AppModel.download`; generic source HTTP 503 | Preserve provenance, status and allowlisted reason; Apple auth 503 must stop auth, generic download 503 stays transport | All 503 classified authentication; download status discarded |
| G10 High for future automation | AppModel diagnostics in memory, `RecoveryBudget` memory-only | Persistent inspection records with atomic writes, strict schema, terminal verification, restart interruption; do not schedule/sign/install | Restart loses operation context; future mutation automation blocked |
| G11 High | `InstallationPreflight`; insufficient evidence or group/team differences | Pure three-way update policy with explicit missing evidence and data/keychain warnings; no install executor | Helper only checks identifiers/team and two booleans |
| G12 Medium | Pairing schema and certificate display | Valid DER/profile/certificate-key/device-coverage tests plus live paired service tests; distinguish parsed from trusted | Synthetic negative/Keychain tests only; unresolved |
| G13 Medium | Protected library/download/Files paths | Locked-device protection, iCloud provider, download interruption/HTTP tests and secret-free diagnostic export | Simulator import passes; real provider/network/hardware paths unverified |
| G14 High | All release/automation surfaces | Preserve explicit gates, no auto revoke/uninstall/account change; keep PRs draft/unmerged | Baseline obeys policy; regression must preserve it |

Phase 1 gate: critical gaps G01–G04 are explicitly unresolved blockers. This permits inspection/security foundation fixes, not higher-level signing/install automation. V1 is Experimental, not completed. V2 remains blocked by V1 prerequisites; no fundamental impossibility is claimed.

## Verification addendum

G05/G06/G07 are fixed in V1 source 1f6d402 and the stacked V2 branch: 15 portable tests and 18 total hosted V1 tests passed in run 41174314865. V2 journal, update policy and provenance changes G09–G11 have pure regression tests; inspection history/export passed in hosted run 41173560308, while mutation automation is absent. G08 now has bounded structural/architecture/encryption and XML entitlement inspection with portable regression tests, but still lacks full cryptographic/resource/DER semantics and target compatibility. G12 has bounded DER date/OU inspection and valid synthetic certificate tests; existing-key proof is implemented but its newer hosted run is pending. No profile CMS authenticity or real paired-device test has passed.

The isolated CodeSignKit experiment verifies synthetic primitives but Apple's verifier rejected its output. It does not fix G01. G01–G04 remain unresolved critical blockers. Source after 0ab2990 has 42 passing portable tests; newer hosted validation is explicitly pending in TEST_RESULTS.md. No mocked Apple success or actual device success exists.

### Current verification addendum (supersedes pending notes above)

Run41201716117 source2bf03b6 passed57 unique automated tests:47 core9 native app1 UI, plus Simulator/unsigned iPhone builds and own-IPA inspection. Accessible matching-key proof and mismatch rejection passed with newly generated test credentials; no real developer identity was used. Offline Apple-root candidate analysis refuses signing authorization. Source-traced Lockdown/Remote Pairing plist detection, replacement approval/cancellation and passive runtime-export privacy passed automated tests only. G12 remains open for real pairing/Apple eligibility.

Lab run41201328417 source1cfbed8 passed native Mac structural/cryptographic verification after candidate fixes, independent primitive/tamper checks and verifier iOS compilation. G01 is still open: synthetic non-Apple identity, no authenticated profiles/developer authorization/on-device signer/install acceptance. Source1a39bfd adds locally tested Swift-generated synthetic identities (8 lab tests), pending hosted run41203139779. No change to critical G01–G04 status or disabled mutation engines.
