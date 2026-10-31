# OmniSign V1 roadmap

Target: stock iPhone 17 / iOS 27.0.1, no paid APIs, one-time Windows bootstrap permitted. Current classification: **V1 Experimental**. This roadmap records evidence, not predicted completion dates. An unsigned IPA is a build artifact, not proof of sideloading functionality.

## 1. Repository and build foundation

- [x] Create isolated feature branch based on the owner's dedicated repository.
- [x] Implement native five-section SwiftUI source and portable Swift package.
- [x] Trace actual upstream signing/install functions and record pinned source references.
- [x] Implement real IPA import/inspection, bounded archive checks and persisted library.
- [x] Pass 11 portable XCTest cases and CLI accept/reject checks locally.
- [x] Add standard hosted macOS workflow for tests, Simulator compilation, unsigned iPhone compilation, IPA packaging and evidence upload.
- [x] Verify [hosted macOS workflow](https://github.com/onlykappa/omnisign-ios/actions/runs/41171713736) passes; Xcode 16.4, iPhoneOS SDK 18.5, iPhone 17 Pro Max Simulator / iOS 26.2. Artifact hash is recorded in TEST_RESULTS.md.
- [x] Open [draft PR #1](https://github.com/onlykappa/omnisign-ios/pull/1) and keep main unchanged.

## 2. Inspection and local security

- [x] Add local Keychain adapter and legacy pairing schema checks; Keychain save/update passed in Simulator.
- [x] Add conservative profile/entitlement/preflight policies and bounded recovery.
- [x] Reject unsafe archive structures and missing recognized framework metadata.
- [x] Validate restored library metadata/package references, cap actual copied bytes and recheck profile expiration at use; 15 portable tests passed at the audit-hardening checkpoint.
- [x] Pass hosted Simulator tests for actual app IPA import/reload, Keychain save/update and five-section navigation.
- [ ] Validate file-protection enforcement on hardware, Files/iCloud providers and HTTPS streaming.
- [ ] Parse all relevant Mach-O architectures, load commands, encryption and typed entitlements.
- [ ] Inspect developer certificate validity, Apple authorization and matching private-key ownership.
- [ ] Validate CMS profile trust, device coverage, per-target identifiers, capabilities and expiration.

## 3. Independent local signing

- [ ] Resolve SideSign license grant or choose a complete licensed alternative; audit and pin every transitive dependency.
- [ ] Implement reviewed local Apple authentication/anisette; never transmit credentials to third-party services.
- [ ] Reuse an existing certificate/private key without revocation; obtain exact app/extension profiles.
- [ ] Sign nested native code then parent; independently verify signatures and package integrity.
- [ ] Demonstrate signing a disposable IPA on the physical target without SideStore installed or an active computer.

## 4. Authorized device transport and refresh

- [ ] Establish a feasible free-only VPN/device-service provisioning path; a free development account cannot be assumed to provision a packet-tunnel extension.
- [ ] Validate imported pairing credentials and target-device handshake; implement service probes and bounded transfer.
- [ ] Install and verify inventory/version/profile, then verify launch in the foreground.
- [ ] Refresh and update a disposable app in place; verify saved-data survival with computer disconnected.
- [ ] Test interrupted operations, lost VPN, expired profiles, locked device and account restrictions.
- [ ] Add expiration reminders and supported background opportunities after manual refresh works.

## 5. Owner application compatibility and release gate

- [ ] Inspect owner-supplied custom Kodi and KappaForge IPAs without modifying installed apps.
- [ ] Establish per-app identifier/team/capability compatibility; never automatically delete or replace either app.
- [ ] Demonstrate data-preserving updates on the actual target before claiming support.
- [ ] Complete every step in docs/DEVICE_ACCEPTANCE.md with redacted evidence.
- [ ] Obtain owner review before merge, deployment or release. Only then consider **V1 Functional** classification.

Milestones 3–5 require missing signing/transport work and physical-device evidence; a hosted Simulator cannot close those gates. No checkbox may be marked complete based on a mock operation. See docs/NEXT_ACTIONS.md and docs/PHASE0.md for dependencies and constraints.

Strict CI follow-up7ff18d3 prevents masked packaging/inspection failures. Local15 tests/CLI + shell/YAML checks passed; hosted run41204248419 pending. This changes verification reliability, not disabled signer or device-service capabilities.
