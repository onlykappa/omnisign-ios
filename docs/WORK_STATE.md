# Persistent handoff / source of truth

Owner wants all progress saved in GitHub, both PRs kept draft and unmerged, V1 finished before V2 autonomous signing/install work. Main must stay unchanged. Do not merge, release, deploy, revoke certificates or uninstall owner apps. Never ask for credentials/private keys/pairing secrets in chat or GitHub.

- Repository: onlykappa/omnisign-ios.
- V1 branch: `feat/v1-experimental`; draft PR #1. Roadmap: `/ROADMAP.md`.
- V2 branch: `feat/v2-foundations`; draft PR #2 open, stacked on V1. Roadmap: `docs/v2/ROADMAP.md`.
- V1 is Experimental. Real sign/install/refresh are missing and disabled, not working engines awaiting only hardware tests.
- V1 successful hosted source: 43ec5d9, Actions run 41171713736, 14 automated tests; Xcode 16.4, SDK 18.5, Simulator iPhone 17 Pro Max/iOS 26.2. This is NOT physical iPhone 17/iOS 27.0.1 evidence.
- Local workspace is Linux. Portable Swift 6.0.2 toolchain in scratch; scripts/test.sh uses swift on PATH. Hosted public standard macOS runner builds Xcode free of a Mac purchase; unsigned artifacts expire after seven days and are not releases.
- Phase 0 and immutable source/license trace: docs/PHASE0.md, docs/SOURCE_REFERENCES.md, docs/research-lock.json. SideSign license unresolved; no upstream signer/transport code linked. ZIPFoundation is the only linked dependency.

Resume sequence: fetch repository; inspect both PRs/branches and recent Actions results; read this file, both roadmaps, TEST_RESULTS.md and docs/v2/V1_GAP_AUDIT.md; run existing tests before edits. Check boxes only on actual evidence. Commit and push tested checkpoints so work survives context/environment loss. Save exact run URLs, source SHAs, failures and blockers. A context limit does not authorize abandoning the task or relabeling missing workflows as complete.

Current task: V2 audit and safe foundation regressions only; critical V1 signer/transport/hardware gaps remain unresolved. No mutation automation may be enabled. Continue with docs/v2/ROADMAP.md in dependency order. Owner approval is required for any merge, even if V1 later becomes functional. Once V1 is demonstrably complete, leave PR #1 unmerged and continue V2 on the stacked branch as instructed.

Latest checkpoint: b9b1a55 on V2 includes validated restore/bounded copies, use-time profile expiry, persistent inspection journal, redacted export, source-aware failure and conservative update policies. Local 27 tests passed; hosted run 41172825357 is pending and must be checked. Mutation engines remain unavailable. Next: inspect hosted result, fix actual failures, audit/experiment with a licensed offline signer independently; do not wire an unverified signer into app automation.
