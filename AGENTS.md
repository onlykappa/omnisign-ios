# OmniSign continuity and safety

Read `docs/WORK_STATE.md`, `ROADMAP.md`, `docs/v2/ROADMAP.md`, the relevant test results and Phase 0 before continuing. Inspect live PR/branch/test state; never assume a prior context's pending run passed.

The owner wants tested progress committed/pushed to GitHub at meaningful checkpoints so context/runtime limits do not lose work. Update roadmaps with actual evidence and keep exact failures, source SHAs, run URLs, blockers and next commands in the handoff. Do not mark future work done merely because a type/UI/placeholder exists.

Prioritize V1 core signing/install/refresh gaps before V2 automation. PR #1 (`feat/v1-experimental` → main) and PR #2 (`feat/v2-foundations` → V1) must remain draft/unmerged, even if complete. No automatic merge, deployment, publication or release. Isolated branch rebases/checkpoints are not release authorization.

Keep unverified mutation engines disabled. No mocks as Apple/device proof, no certificate revocation, owner-app uninstall/erase, undisclosed auth server, secret logging or credential collection. No physical-device pass without real evidence. Never request private keys, passwords, session tokens or pairing secrets in chat/GitHub. Use disposable apps for acceptance.

Run relevant automated tests before committing code; use hosted standard macOS CI for Xcode verification. Pure policies and simulated test inputs must be labeled as such. Do not add an active recovery/scheduling layer over a missing signer/transport. At most five suitable evidence-distinct attempts; stop authentication/security/rate restrictions. Preserve critical blockers rather than inventing a workaround.
