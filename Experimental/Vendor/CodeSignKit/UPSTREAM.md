# Experimental CodeSignKit source mirror

Upstream: https://github.com/mahee96/CodeSignKit/tree/d0c67710fda9a2646b9e829cb2cf443892728371 . Upstream copyright headers and the full AGPL-3.0 license are preserved. This directory and combined signing laboratory are AGPL-3.0-only, not part of the MIT app dependency graph. Corresponding experimental source is present in this repository; preserve it and all transitive notices in any redistribution. No production redistribution approval is implied.

Only upstream `Sources/` is mirrored. The minimal package manifest links exact swift-crypto 4.3.1 and swift-asn1 1.6.0; upstream CLI/tests/checksum-pinned OpenSSL test binary target are excluded. Dependency locks are in the consuming lab package. No closed/private signing service, Apple authentication, installation code or owner credentials are added.

Changes relative to that source revision:

- RequirementsCompiler: designated requirement set entry uses type **3**, not host requirement type 1. Certificate subject OU equality uses match operation **1**, not matchExists operation 0. Regression tests pin these protocol values and the Mac harness asks `csreq` to parse the generated blob; native codesign acceptance remains separately required.
- CodeResourcesBuilder: read errors propagate rather than hashing empty data; bounded streaming hashes replace whole-file fallback reads; sequential result construction removes unsynchronized concurrent Array writes; symlink/nonregular/escaped resources and excessive counts/bytes are rejected. These are isolated candidate fixes, not a complete signer security audit.

Known unresolved issues include PKCS#12 MAC/key selection audit, fallback embedded certificate-chain behavior, certificate/time/revocation/profile eligibility, full resource rules and native-policy compatibility, device-specific code format/entitlements and physical-device signing/install tests. The lab only accepts a generated self-issued `OmniSign Disposable Lab` / `OMNILAB123` identity and disposable org.omnisign.lab app, and rejects real Apple-issued identities. Do not link this mirror into the application or call it a production signing engine.
