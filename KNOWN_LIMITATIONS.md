# Known limitations

- Essential signing/install/refresh backends are absent. ExperimentalEngine is an explicit disabled boundary, not a signing implementation.
- No Apple authentication, anisette generation, private-key import/reuse, certificate expiration extraction, certificate issuance, profile acquisition/CMS validation, cryptographic signature verification, entitlements extraction or binary rewriting.
- No live VPN/pairing probe, device-service connection, install inventory, launch verification, update comparison against installed versions or expiration scheduling.
- Profile parsing and entitlement/preflight policy helpers are portable tests, not a complete certificate/provisioning manager.
- Legacy pairing schema and DER certificate UI paths are uncompiled and untested on iOS. Remote pairing formats and PKCS#12 are unsupported.
- Mach-O checks are shallow. Native libraries are inventoried by dylib suffix; bundles by Info.plist. Obfuscated/missing bundle metadata or other native resource layouts may escape inventory. No signing readiness is inferred.
- Archive limits can exclude large Kodi builds. Symlinks are rejected even when legitimate. ZIP64/unsupported compression behavior depends on ZIPFoundation.
- No application icon decoding; generic icons avoid trusting unvalidated images. No verified Liquid Glass rendering or accessibility/UI tests.
- Diagnostic context is deliberately sparse and in memory; export, per-app logs and persistence are not implemented.
- No automatic cleanup after a process crash, transactional database, deduplication, importer cancellation UI or download progress percentage. Downloads use an indeterminate progress state.
- Build project generation, iOS compilation, simulator/device execution and installable signed IPA generation need macOS/Xcode and authorized signing assets. None ran here.
- No provisioned remote OmniSign repository, so no draft PR was opened. Unrelated repositories were not changed.
