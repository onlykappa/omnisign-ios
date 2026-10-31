# Offline Apple root pins

Retrieved 2026-10-31 over HTTPS from Apple's public certificate-authority endpoints. These are public CA certificates, not owner credentials, developer identities or private keys. No on-device network fetching occurs in AppleDevelopmentTrust. SHA-256 is computed over the exact DER bytes.

| Official source | DER SHA-256 |
|---|---|
| https://www.apple.com/appleca/AppleIncRootCertificate.cer | b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024 |
| https://www.apple.com/certificateauthority/AppleRootCA-G2.cer | c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050 |
| https://www.apple.com/certificateauthority/AppleRootCA-G3.cer | 63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179 |

Only the public G3 root is copied into test resources for hash/negative-identity tests, unmodified, attributed to Apple. No root is installed into a trust store or made trusted by the app. The application contains hash pins and asks the OS to validate a chain with network fetching disabled, then checks that chain's root pin, development marker, time and unambiguous candidate team OU. It does not trust a marker, issuer name, provided root or local user CA alone.

An offline candidate is NOT authorization to sign: revocation/portal status, matching key use, profiles, entitlements, app/device compatibility and independent signatures remain separate unresolved gates. Missing intermediates/cache can block a valid certificate; the app must report that rather than silently fetching, creating or revoking identities. Pin updates require review against official sources. No genuine Apple development leaf/private-key positive test is available; only public root and forged-marker rejection tests are provided.
