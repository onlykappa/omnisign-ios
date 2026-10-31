# V2 device acceptance — NOT RUN

Do not bypass disabled engines. Complete V1 signer, transport and license gates first. Use physical iPhone 17/iOS 27.0.1 and a disposable app with v1/v2 builds, a native framework, extension and an editable persisted value. Never use real Kodi/KappaForge for destructive tests. The hosted iPhone 17 Pro Max/iOS 26.2 Simulator is not this target.

1. Record actual model/OS build, OmniSign/source/dependency revisions, public certificate fingerprints/expiration and test versions in a private local record; redact identifiers before sharing.
2. Perform owner-authorized initial bootstrap, then disconnect USB and shut down desktop signing/install services. Keep the computer disconnected for every subsequent signing/install/refresh/update step.
3. Import and fully inspect the disposable app. Validate architecture, real entitlements, exact identifiers/team, Apple-trusted certificate/private key and compatible CMS profiles.
4. Sign on the iPhone and independently verify all nested signatures/resources/profiles. A command's zero status is not a pass.
5. Establish a validated paired authorized device-service transport; verify storage and endpoint compatibility. Transfer/install and require completion plus inventory/version/profile evidence.
6. Launch in the foreground. Enter and save a unique value. Reopen and confirm it.
7. Refresh manually before the verified profile expires. Confirm new signing/profile validity, launch and saved value.
8. Install v2 in place with matching reviewed identity/groups. Verify version, launch and saved value. Stop if replacement/deletion would be needed; require explicit owner confirmation before any destructive test, limited to disposable apps.
9. Restart OmniSign and verify durable history. Interrupt a disposable transfer/refresh, temporarily lose VPN, and restart. Require Interrupted/Failed with useful context, no automatic success or blind replay. Revalidate before safe reconnect/resume.
10. Exercise expired sessions/credentials/pairing, invalid responses, 2FA, HTTP 429/503 and account restrictions using safe controlled tests. Never repeatedly submit credentials or issue/revoke certificates to consume an attempt budget.
11. Demonstrate at most five appropriate evidence-distinct recovery attempts where safe; stop security-sensitive failures. Test denied notification/background opportunities and the explicit foreground fallback. No uninterrupted background guarantee.
12. Export redacted operation history, manually inspect for secrets, and record exact observed outcomes. Only after this succeeds evaluate separately owner-authorized Kodi/KappaForge identity/capability compatibility without automatic deletion.

Pass requires actual target-device sign/install/launch/refresh/update and saved-data survival with no active computer, including restart and temporary transport failure recovery. Missing backend or desktop dependency is a failed/incomplete gate, not a skipped success. Automated tests cannot replace this procedure.

Prepared fixture: [Tests/DeviceFixture](../../Tests/DeviceFixture/README.md) provides unsigned1.0/1.1 saved-value builds (run41203656751). It has no nested framework/extension and does not replace that coverage requirement. Check free-account app/identifier slots without deleting owner apps; lack of a slot is an unresolved acceptance constraint. No physical results exist.
