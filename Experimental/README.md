# Disabled engine boundary

The executable boundary is `ExperimentalEngine` in `Sources/OmniCore/Safety.swift`. Every operation throws `unavailable`; no mock result, adapter or toggled entitlement can enable installation. No upstream signing code has been linked or copied.

Before adding an adapter: resolve SideSign's missing license grant and audit all transitives; pin every source revision; remove unsafe upstream verbose logging and any certificate-revocation paths; verify exact app/extension profile matching rather than fallback-to-first-profile; implement independent post-sign validation; validate paired device service transport on the target device. Keep mutation APIs inaccessible until disposable-app acceptance completes. Source research is recorded in docs/PHASE0.md.
