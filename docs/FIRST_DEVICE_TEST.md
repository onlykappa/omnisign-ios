# First physical-device test: inspection preview

Status: **available for owner preview after authorized Windows bootstrap; NOT RUN**. A newer Simulator rerun41203656725 failed Library navigation assertions; root cause is unresolved and diagnostic run41204383402 is pending. The exact artifact below comes from the earlier passed57-test run; report any tab-navigation failure during preview. This test covers the real inspection app, not independent signing/install/refresh. No Mac purchase is needed. The app must never replace Kodi/KappaForge, revoke certificates or infer installation from an import.

## Obtain the tested build

- Tested source: `2bf03b6611a5182812e3d64d00038abd1a3a285b` on draft PR#2; [successful run41201716117](https://github.com/onlykappa/omnisign-ios/actions/runs/41201716117).
- Download [unsigned IPA artifact](https://github.com/onlykappa/omnisign-ios/actions/runs/41201716117/artifacts/13042708704) and [build evidence](https://github.com/onlykappa/omnisign-ios/actions/runs/41201716117/artifacts/13042918146). GitHub sign-in may be needed; artifacts expire after seven days. These are Actions artifacts, not a release.
- Extract the outer downloaded ZIP only. Check the contained IPA using PowerShell: `Get-FileHash -Algorithm SHA256 -LiteralPath .\OmniSign-UNSIGNED-experimental.ipa`.
- Expected inner IPA SHA256 (reported by the runner): `0932d21e867245dcf44317b0bcd3b2ebf18b217ecd000612bac42c1a35050696`. This is distinct from the artifact ZIP digest. Stop if mismatched.
- Follow [Windows bootstrap](WINDOWS_BOOTSTRAP.md). Keep passwords/2FA/private keys/pairing material local to trusted software. Never upload them to chat, GitHub or Actions. If the bootstrap tool proposes revocation, removal/replacement of another app or account-security workarounds, stop. OmniSign cannot refresh itself yet.

## Execute only the preview tests

1. Record the actual model and OS build from iPhone Settings. Launch OmniSign; confirm Experimental, Signing Unavailable, Installed apps Unknown and transport Not probed. Record whether it is actually iPhone17/iOS27.0.1; SDK/minimum deployment target are not compatibility evidence.
2. Copy an authorized disposable IPA into Files. The downloaded **unsigned OmniSign IPA itself** may be inspected as a harmless archive; importing it does not install or overwrite anything. Use Home → Import IPA. Check real name/version/bundle identifier, native-image metadata, warnings and children-first target list.
3. Confirm imported apps count increases, installed apps remains Unknown, and Install/Update/Refresh are disabled. Inspection Completed means only persisted archive inspection.
4. Fully close/reopen OmniSign. Confirm the imported metadata and inspection history survive. Repeat from iCloud Drive if available, recording provider/file access failures without sharing private source URLs or file paths.
5. Try a plain text file with an `.ipa` suffix. Require rejection and no new successful library/history entry; the previous import must remain. Do not use suspicious downloaded malware as a test fixture.
6. Open Signing. Local certificate/profile/pairing inspection is optional. Metadata and schema detection must still say unverified. There is no account login or installation handshake. Never import/export pairing secrets merely to report a preview result. Replacing locally stored pairing requires explicit approval, and cancellation must preserve it.
7. Open Home/Diagnostics while network or an existing VPN changes. The path/tunnel observation may change, but transport must remain Not probed. No VPN installation/configuration is required for preview tests; observed tunnels do not prove pairing or installation readiness.
8. Diagnostics → Prepare redacted history export → Share redacted history. Save locally and inspect it first: schema2 should contain whitelisted runtime/build/network observations and operation records only. No passwords, keys, tokens, pairing bytes, source URLs, Apple IDs, bundle/team IDs or raw backend errors. Device family/model and OS/build plus generated UUID/timing are intentionally included.
9. Record outcome against the template below. Share only manually reviewed redacted output. Keep any real identifying metadata private. Do not declare signing/install/refresh success from these tests.

## Result template

```text
Source: 2bf03b6 / run41201716117
Actual model / OS build:
Bootstrap tool/version (no account identifiers):
Launch: NOT RUN / PASS / FAIL
Files import and metadata: NOT RUN / PASS / FAIL
iCloud provider: NOT RUN / PASS / FAIL
Restart persistence: NOT RUN / PASS / FAIL
Invalid archive rejection with prior state preserved: NOT RUN / PASS / FAIL
Disabled mutation controls and unverified transport: NOT RUN / PASS / FAIL
Redacted export manually reviewed: NOT RUN / PASS / FAIL
Observed errors (redacted codes/stage only):
Independent Apple signing: NOT RUN — backend missing
Installation/refresh/update/data survival: NOT RUN — backends missing
```

Full product acceptance remains [DEVICE_ACCEPTANCE.md](DEVICE_ACCEPTANCE.md) and [V2 acceptance](v2/DEVICE_ACCEPTANCE.md), blocked until the signer/account/profile/device-service implementations exist. This preview supplies useful physical evidence but does not close those gates.
