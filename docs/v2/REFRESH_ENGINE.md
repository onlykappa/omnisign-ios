# Refresh engine

Operational status: **Missing / Blocked**. No foreground refresh, refresh-all, profile acquisition, verified reinstall, background refresh scheduling or expiration notification backend is active. `ExperimentalEngine` and the journal block refresh operations.

A decoded profile expiration is revalidated at use. This policy helper is not a signed-profile trust check or a device expiration observation. No fixed seven-day validity is assumed; future scheduling must use actual verified expiration and account/device constraints.

After V1 manual sign/install/refresh has physical acceptance: implement explicit foreground refresh first, verify the newly embedded profile and launch/data retention, then implement persistent refresh-all with per-app outcomes. Add owner-authorized local expiration notifications and only supported opportunistic background tasks. Persist interruptions without blind replay, revalidate inputs before any resumed step, and enforce evidence-distinct bounded nonauth recovery.

iOS may suspend or prevent execution and VPN transport may be unavailable. A user-triggered foreground fallback must remain available. No guaranteed automatic background refresh, perpetual validity or zero-PC completion claim is permitted without the actual no-computer acceptance sequence.
