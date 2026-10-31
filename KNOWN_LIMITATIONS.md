# Known limitations

- Essential signing/install/refresh backends are absent. ExperimentalEngine is an explicit disabled boundary, not a signing implementation.
- No Apple authentication, anisette generation, private-key import/reuse, certificate expiration extraction, certificate issuance, profile acquisition/CMS validation, cryptographic signature verification, entitlements extraction or binary rewriting.
- No live VPN/pairing probe, device-service connection, install inventory, launch verification, update comparison against installed versions or expiration scheduling.
- Profile parsing and entitlement/preflight policy helpers are portable tests, not a complete certificate/provisioning manager.
- The app and its UI paths compile. Keychain save/update and invalid DER rejection passed in Simulator; real legacy pairing and development-certificate acceptance remain untested. Remote pairing formats and PKCS#12 are unsupported.
- Mach-O checks are shallow. Native libraries are inventoried by dylib suffix; bundles by Info.plist. Obfuscated/missing bundle metadata or other native resource layouts may escape inventory. No signing readiness is inferred.
- Archive limits can exclude large Kodi builds. Symlinks are rejected even when legitimate. ZIP64/unsupported compression behavior depends on ZIPFoundation.
- No application icon decoding; generic icons avoid trusting unvalidated images. Navigation passed a hosted Simulator UI test; full visual/accessibility testing and Liquid Glass behavior are unverified.
- Diagnostic context is deliberately sparse and in memory; export, per-app logs and persistence are not implemented.
- Corrupt metadata/missing package references fail closed and copies enforce byte caps. No automatic cleanup after a process crash, transactional database, deduplication, importer cancellation UI or download progress percentage. Downloads use an indeterminate progress state.
- Project generation, Simulator execution and unsigned iPhone compilation/IPA packaging passed on hosted Xcode. Signed IPA generation and physical-device execution still need authorized signing assets and hardware.
- Repository: onlykappa/omnisign-ios. Hosted build and draft-PR results are tracked in TEST_RESULTS.md. Unrelated repositories are not modified.
