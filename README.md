# OmniSign

**V1 Experimental — incomplete sideloading manager.** Real Swift IPA inspection and persistence exist. Signing, installation, refresh, Apple login, launch verification and data-preserving updates have not been implemented or demonstrated. No production release or installable IPA was produced here.

Native SwiftUI source provides Home, My Apps, IPA Library, Signing Center and Diagnostics. Import from the Files picker (including On My iPhone and iCloud providers) or an explicitly entered HTTPS URL. Imports are copied into protected local application storage and inspected; they are never marked installed. DER certificate inspection and legacy pairing-plist schema inspection use local Keychain storage. The app uses dark native controls with purple accents; iOS 27 Liquid Glass appearance has not been visually verified.

## Build and test

The portable Swift core can be tested on Linux or macOS with Swift 6.0+ and zlib development headers:

```sh
python3 scripts/fixtures.py
swift test
swift run omnisign-inspect /path/to/authorized.ipa
```

On a Mac, install free Xcode and the open-source XcodeGen tool, then:

```sh
xcodegen generate
xcodebuild -resolvePackageDependencies -project OmniSign.xcodeproj -scheme OmniSign
xcodebuild -project OmniSign.xcodeproj -scheme OmniSign -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

Open the generated project in Xcode and select your authorized personal development team for initial device installation. Provisioning and device registration must be valid. No credentials or team identifier are checked in. To create an unsigned bootstrap archive on macOS:

```sh
xcodebuild -project OmniSign.xcodeproj -scheme OmniSign -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO build
mkdir -p DerivedData/Bootstrap/Payload
cp -R DerivedData/Build/Products/Release-iphoneos/OmniSign.app DerivedData/Bootstrap/Payload/
(cd DerivedData/Bootstrap && zip -qry ../OmniSign-unsigned.ipa Payload)
```

The resulting IPA is **unsigned and cannot be installed directly**. An authorized initial signing method must sign it. Windows bootstrap is possible through a separately obtained trusted signing tool; Windows does not replace Xcode for building this SwiftUI target. Build commands above have not run in this Linux environment. Use an Xcode version with an SDK supporting the target OS/device; deployment target 17.0 is a minimum, not evidence of iOS 27 compatibility.

See [Phase 0](docs/PHASE0.md), [test results](TEST_RESULTS.md), [device acceptance](docs/DEVICE_ACCEPTANCE.md), [limitations](KNOWN_LIMITATIONS.md) and [architecture](ARCHITECTURE.md). No paid API, server credential collector, revocation, uninstall, release or auto-merge is included. No remote repository was provisioned; work is local on `feat/v1-experimental`.
