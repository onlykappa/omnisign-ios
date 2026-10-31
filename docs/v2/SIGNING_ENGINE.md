# Signing engine

Operational status: **Missing / Blocked**. `ExperimentalEngine.perform` still throws unavailable. No real Apple authentication, provisioning acquisition, key-backed identity reuse, nested code signing or independent on-device signature validator is wired into the app. An inventory/signing-order list is not a signing engine.

V1 source trace and pins remain in ../PHASE0.md, ../SOURCE_REFERENCES.md and ../research-lock.json. SideSign lacks a confirmed root license grant at the reviewed snapshot; no code from it is copied or linked. CodeSignKit/AltSign-family alternatives require separate transitive/license/output audits. Public availability and a command's zero exit status are insufficient authorization or validation.

Implemented prerequisites: profile summaries reject malformed identifiers and recheck expiration at use; exact-string entitlement policy remains conservative; update policy warns on keychain/shared-container/data changes. These accept caller-provided metadata and do not verify CMS trust or actual entitlement blobs.

Required implementation order:

1. Choose an appropriately licensed signer, pin every dependency and preserve license/source obligations.
2. Validate executable CPU/load commands/encryption, actual typed entitlements, Apple certificate chain/validity/team and a private-key signing challenge.
3. Authenticate locally using disclosed origins and reviewed anisette/session/2FA handling; stop at security restrictions, malformed responses, expired sessions or rate limits. Never revoke certificates.
4. Obtain compatible profiles for each exact app/extension identity and reconcile groups/capabilities with explicit data-access warnings.
5. Sign children before parents, then independently verify all resource seals, CodeDirectories and CMS/signature/profile associations.
6. Demonstrate independently on the actual target using a disposable app; no SideStore application or active desktop service may be assumed.

No automated certificate creation/revocation or undisclosed third-party auth service exists. An isolated signing experiment may use generated synthetic identities; that would not establish Apple development authorization or iPhone installability.

Progress: certificate date/OU/development-marker metadata, untrusted CMS profile inspection and typed untrusted XML binary entitlements are implemented. Subject OU/OIDs, profile time eligibility and a matching-key challenge are not Apple authorization. The main engine is still unavailable. The independent offline lab signed four disposable targets and passed independent mathematical checks, but Apple's verifier rejected the candidate output; see TEST_RESULTS.md. CodeSignKit is isolated with its AGPL license and dependency lock, never copied into or linked with the app. Full production transitive/security audit remains incomplete.
