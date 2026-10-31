# OmniSign

**V1 Experimental — incomplete sideloading manager.** Real Swift IPA inspection and persistence exist. Signing, installation, refresh, Apple login, launch verification and data-preserving updates have not been implemented or demonstrated. A hosted unsigned IPA is available for authorized bootstrap testing; no production release or directly installable signed IPA was produced.

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
python3 scripts/generate-test-identity.py # disposable local XCTest resources; never owner credentials
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

The resulting IPA is **unsigned and cannot be installed directly**. An authorized initial signing method must sign it. Windows bootstrap is possible through a separately obtained trusted signing tool; Windows does not replace Xcode for building this SwiftUI target. Build commands above cannot run in the local Linux environment; the equivalent hosted Xcode workflow has now passed (see TEST_RESULTS.md). Use an Xcode version with an SDK supporting the target OS/device; deployment target 17.0 is a minimum, not evidence of iOS 27 compatibility.

See [Phase 0](docs/PHASE0.md), [test results](TEST_RESULTS.md), [device acceptance](docs/DEVICE_ACCEPTANCE.md), [limitations](KNOWN_LIMITATIONS.md) and [architecture](ARCHITECTURE.md). No paid API, server credential collector, revocation, uninstall, release or auto-merge is included. The dedicated repository is https://github.com/onlykappa/omnisign-ios . Work stays on `feat/v1-experimental`; no automatic merge or release is configured. See [ROADMAP.md](ROADMAP.md).

## Build without owning a Mac

The `iOS experimental build` GitHub Actions workflow uses a standard `macos-15` hosted runner. In this public repository, standard hosted runner execution is available without buying a Mac. No paid runner or service is configured. The workflow runs on feature-branch pushes (manual dispatch becomes available once the workflow is on the default branch), tests the portable core, generates the Xcode project, compiles for Simulator and iPhone, and uploads a seven-day `OmniSign-UNSIGNED-experimental` artifact plus build evidence. It neither publishes a release nor merges a PR.

See [Windows bootstrap](docs/WINDOWS_BOOTSTRAP.md) for download, hash checking and local initial-signing guidance.

An unsigned artifact still requires owner-authorized initial signing on Windows or another supported method before it can be installed. Simulator compilation is not evidence of iOS 27.0.1 compatibility or independent signing/install/refresh. Check the actual workflow result before assuming an artifact exists.

Latest V2 inspection-preview build: [run41201716117](https://github.com/onlykappa/omnisign-ios/actions/runs/41201716117), source2bf03b6. **57 automated tests passed** (47 core, 9 native app, 1 UI), Simulator/unsigned iPhone builds passed. [First phone-preview test instructions](docs/FIRST_DEVICE_TEST.md) explain Windows bootstrap and evidence collection. Independent signing, installation and refresh remain disabled. V1 hardened source1f6d402 also passed18 tests in run41174314865.

V2 work is queued in [draft PR #2](https://github.com/onlykappa/omnisign-ios/pull/2), stacked on unmerged V1. See [persistent handoff](docs/WORK_STATE.md) and [V2 roadmap](docs/v2/ROADMAP.md). New inspection/certificate/reliability foundations are not authorization to sign or install. The separate AGPL offline laboratory verifies synthetic cryptographic primitives only; Mac native structural/cryptographic verification accepted the later synthetic output in run41201328417; its non-Apple identity provides no Apple development authorization or phone-installability proof. No physical-device workflow is claimed.
