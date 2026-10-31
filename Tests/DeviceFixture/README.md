# Disposable physical acceptance fixture

MIT-licensed standalone SwiftUI app. No dependency on OmniSign's account/signer/transport engines, no network/Keychain/credential collection, and no owner-app identifiers. A user-entered **non-sensitive** value and save counter use local UserDefaults via AppStorage; this is test data, never a credential-storage facility.

[Run41203656751](https://github.com/onlykappa/omnisign-ios/actions/runs/41203656751) built source `d5632a9`: unsigned1.0/build1 and1.1/build2 with the same `org.omnisign.acceptance.disposable` bundle identifier. Plist versions/builds and arm64 Mach-O were checked. [Artifact13043850395](https://github.com/onlykappa/omnisign-ios/actions/runs/41203656751/artifacts/13043850395) includes both unsigned IPAs, SHA256/status JSON and build logs; seven-day retention, not a release. Nothing has run on a phone.

To rebuild on macOS with free Xcode/XcodeGen:

```sh
xcodegen generate --spec Tests/DeviceFixture/project.yml --project Tests/DeviceFixture
xcodebuild -project Tests/DeviceFixture/OmniSignAcceptance.xcodeproj -scheme OmniSignAcceptance -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath /tmp/omnisign-test-v1 CODE_SIGNING_ALLOWED=NO MARKETING_VERSION=1.0 CURRENT_PROJECT_VERSION=1 build
# Repeat with separate derivedDataPath, MARKETING_VERSION=1.1 and CURRENT_PROJECT_VERSION=2.
```

The workflow `.github/workflows/device-fixture.yml` packages exact Payload archives and records hashes. The output is unsigned and cannot be installed directly. No signing identity/password/team is checked into the project.

Once real OmniSign signing/installation exists, use the fixture for [device acceptance](../../docs/v2/DEVICE_ACCEPTANCE.md): sign/install1.0 on the phone, launch and save a unique value, close/reopen, refresh/reopen, update1.1 in place, reopen and check both saved value and version. Record exact observed results. Signing the fixtures with a Windows tool tests that tool's workflow, not OmniSign zero-PC capability. Do not uninstall between versions or infer success from an uploaded IPA.

Check available free-provisioning app/identifier slots first. OmniSign plus this test app may not fit alongside existing owner apps; a slot shortage is a blocker, not authorization to uninstall Kodi/KappaForge. A signing-team change or bundle-ID transformation can alter data access. Keep both fixture builds under one reviewed identity/identifier mapping and stop on replacement prompts. No data recovery is promised after uninstall.

This fixture exercises ordinary application launch/local persistence only. It contains no framework or extension, so it does not satisfy nested-code device coverage. The separate signing lab builds nested framework/extension/dylib Mach-O fixtures for cryptographic tests, not launchable-device acceptance. All physical launch, refresh, in-place update and data-preservation outcomes remain **NOT RUN**.
