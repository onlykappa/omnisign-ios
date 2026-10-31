# Security audit — provisional

No credentials, keys, pairing secrets or user IPAs were supplied. No account login, certificate mutation, installed-app mutation or physical transport occurred. Only ZIPFoundation is linked to the app; signing/transport upstreams remain research references.

| Surface | Implemented control | Remaining risk / verification |
|---|---|---|
| IPA/archive import | Path/symlink/canonical collision/CRC/expanded bounds; actual-byte copy cap; metadata restore checks | Full fuzzing, Mach-O structure, executable encryption and signatures missing |
| Local index | Atomic bounded document, validated nonempty bundle metadata and referenced regular packages | Single-writer coordinator requirement; crash-orphan recovery and tamper authenticity absent |
| Journal | Atomic actor-owned bounded schema, strict stage/result rules, finite timestamps, interruption on restart | No automatic replay; journal is local metadata, not cryptographic evidence |
| Diagnostic export | Enum/numeric/UUID allowlist; decoded diagnostic message must match fixed safe template | Exports reveal operation timing and generated IDs; no source URL, bundle/team ID or raw error text accepted |
| Credentials | Keychain WhenUnlockedThisDeviceOnly; no passwords requested or Apple backend | Valid development identity/private-key ownership/session lifecycle still missing |
| Pairing | Local schema validation and Keychain storage; no logged secrets | No key relationship/device/expiration/Remote Pairing handshake validation |
| Certificate display | Local basic X.509 trust, network fetching disabled | No full development certificate/team/expiration/private-key eligibility engine |
| HTTPS downloads | Ephemeral session, HTTPS/no embedded credentials, no redirects, time/actual-byte limits, protected temporary file | Live URLSession/iCloud/locked-device tests still required |
| Recovery | Pure policy stops auth/security/rate-sensitive cases, no destructive strategies/executor | No device recovery verified; no blind restart replay |
| Owner apps | No install/uninstall/revoke/erase APIs active | Preservation must be demonstrated per actual app/team/capabilities |

Inspection progress and errors are persisted without secrets; other app diagnostic events remain memory-only. Pairing/certificate replacements are local Keychain updates, not developer certificate revocation. Additional owner-review gates are required before any future identity, credential or existing-installation changes. Basic X.509 trust and decoded profile data never confer install authorization.

No security audit completion or production approval is claimed. Physical file-protection/Keychain behavior, malicious input fuzzing, signature/CMS verification, dependency review and target-device acceptance remain blockers. See V1_GAP_AUDIT.md and ../PHASE0.md.

Latest scope: the app still links only ZIPFoundation. Native identity discovery is scoped by iOS Keychain entitlements and uses UI-fail lookup; the randomized key proof runs only after explicit user action. It does not export private keys or imply Apple eligibility. Disposable generated P12/password XCTest resources are ignored by Git and are not uploaded; the production app target excludes test resources. Profile imports store CMS bytes in local Keychain, not diagnostics. CMS authenticity remains false. The isolated signing lab's AGPL/crypto dependencies have their own source/lock/license scope and cannot be promoted into the app without the unresolved security/license audit. Source review found silent empty-resource hashing and chain/requirements assumptions; controlled experiment success does not resolve those issues.
