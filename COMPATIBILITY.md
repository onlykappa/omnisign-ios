# Compatibility

| Target | Evidence | Status |
|---|---|---|
| Linux x86_64 Swift core | See TEST_RESULTS.md | Automated tests only |
| SwiftUI iOS application | Source and XcodeGen specification | Xcode build not run |
| iPhone 17 / iOS 27.0.1 | No connected hardware or target SDK | Unverified |
| Stock iOS signing/install/refresh | Source research only | Disabled |
| Kodi custom IPA | No owner IPA supplied or changed | Archive support conditional on limits; signing unknown |
| KappaForge IPA | No owner IPA supplied or changed | Archive support conditional on limits; signing unknown |
| Existing data survival | No installation/update attempted | Unknown |

A free development account does not grant unrestricted capabilities, unlimited app IDs, unlimited active apps, permanent profiles or network-extension entitlements. Apple enforces current account/device/profile restrictions. Typical short free provisioning validity must be read from the actual profile rather than hardcoded. A certificate without its private key cannot sign. Re-signing under a different identifier/team can break updates, keychain access, groups or stored data.

LocalDevVPN may be a separate installed companion; this differs from depending on SideStore itself but does not meet a strict single-application interpretation of standalone. A free personal-team build cannot be assumed capable of embedding a working VPN extension. There is no verified self-contained free-only transport solution here. Background execution is opportunistic; no guaranteed recurring refresh or reminders are implemented.
