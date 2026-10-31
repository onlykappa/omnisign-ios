# Installation engine

Operational status: **Missing / Blocked**. No lockdown/Remote Pairing device gateway, VPN/service discovery, device storage query, transfer, installation_proxy call, inventory verification or launch verifier is integrated. All install/update UI actions remain disabled.

`OperationJournal` implements observable durable stages only for actual IPA inspection. It can represent blocked requests for other WorkKinds but never executes them. `SafeUpdatePolicy` is not an installation authorization source. Neither a library import, successful transfer, generated package nor a Completed inspection is installation evidence.

The future pipeline must check device/architecture/storage/identifiers/team/profiles/entitlements before signing; validate the signed package independently; validate pairing key/certificate/device compatibility and handshake; prove service reachability separately from a VPN indicator; transfer and install; inspect installation completion plus actual inventory/version/profile data; then collect foreground launch/data evidence where automatic launch APIs are unavailable.

Safe update decisions: missing installed inventory, mismatched bundle/team and unverified signatures/profiles/entitlements are Blocked. Changed keychain/app groups, downgrade or unproven data retention are Caution. Compatible requires consistent supplied evidence and relevant preservation demonstration, and does not mean completely safe or activate an update. Kodi/KappaForge receive no hardcoded exceptions. Destructive replacement requires explicit owner confirmation and is not implemented. Never automatically uninstall.

Temporary transport recovery is a future reviewed backend capability. No reconnect/resume loop is active. Pairing import recognizes source-traced Lockdown and Remote Pairing plist schemas and requires owner approval for replacement; key/certificate relationships, live pairing validity and handshake remain missing. NWPath availability/utun counts are passive diagnostics and always leave transport notProbed. Free network-extension distribution and target OS compatibility must be demonstrated, not inferred from upstream source.
