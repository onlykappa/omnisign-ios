# Windows bootstrap for an experimental build

A Mac is not required to download and initially sign a GitHub-built IPA. The hosted Xcode workflow must first pass and produce the `OmniSign-UNSIGNED-experimental` artifact. This build supports inspection; independent signing/install/refresh remain disabled.

1. Open the successful `iOS experimental build` run in the repository's Actions tab. Check its source commit and test results. Download the unsigned IPA artifact and build-evidence artifact from that same run. GitHub may require sign-in to download artifacts.
2. Extract the artifact ZIP. The contained `.ipa` is itself a ZIP-format application archive; do not extract or rewrite its Payload. Compare its SHA-256 with `ipa-sha256.txt` in the evidence using PowerShell `Get-FileHash -Algorithm SHA256 -LiteralPath .\OmniSign-UNSIGNED-experimental.ipa`.
3. Obtain a trusted current Windows bootstrap signing tool directly from its official publisher. Sideloadly's official site is https://sideloadly.io/ . Its role is initial signing only; OmniSign does not include or control it. Review the tool's account handling and documentation yourself. No modified installer or downloaded certificate/private-key service is required by this repository.
4. Use your own authorized Apple development account locally in that tool. Follow its official Apple device-driver, trust, Developer Mode and USB instructions. Do not send Apple passwords, pairing credentials, private keys or session tokens to this chat, GitHub issues, Actions secrets or logs.
5. Sign/install OmniSign under its own test identity. Never select Kodi or KappaForge for replacement, deletion, certificate revocation or troubleshooting. Stop at account restrictions or repeated authentication errors.
6. Launch OmniSign. Confirm it clearly says Experimental and signing/device services are disabled. Test IPA import with a disposable authorized file. This is app-preview/import validation, not completion of the independent signing/install acceptance gate.

A free account/profile can expire; read the actual profile expiration from the bootstrap tool. OmniSign currently cannot refresh itself. Keep the Windows bootstrap route available for recovery. Do not rely on this build to preserve access to another installed application. No uninterrupted background refresh or iOS 27 support is established by this procedure.
