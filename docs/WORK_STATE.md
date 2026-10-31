# Current V1 checkpoint — 2026-10-31

Repo onlykappa/omnisign-ios; branch feat/v1-experimental, draft PR#1 → main. Do not merge/release/deploy/revoke/uninstall. Main remains owner initial commit. V2 is stacked draft PR#2 and must also remain unmerged.

V1 classification: **Experimental**. Real Apple authentication/profile acquisition/signing/installation/refresh backends are missing and disabled. No physical iPhone17/iOS27.0.1 acceptance, data survival or owner Kodi/KappaForge operation occurred.

V1 app source1f6d402 passed18 hosted tests (15 portable2 app1 UI), Simulator and unsigned iPhone builds in run41174314865. Latest source7ff18d3 hardens every required workflow shell step with strict error/pipe handling, preventing a packaging/inspection failure from being masked by later output. Local15 portable tests + CLI checks and YAML/bash checks passed. Hosted run41204248419 is pending; never assume it passed.

Latest detailed ongoing state, advanced inspection-preview instructions, isolated signing lab and evidence are on the V2 branch in docs/WORK_STATE.md, docs/FIRST_DEVICE_TEST.md and docs/v2/TEST_RESULTS.md. Do not confuse advanced V2 source with this V1 branch. The lab is excluded from the manager dependency graph and uses synthetic non-Apple assets; it does not close the real signing/install gate. V2 also records failed app rerun41203656725 (Library navigation) and its diagnostic follow-up; do not hide this behind older passing runs.

Next: check hosted V1 run41204248419; continue real signer/independent validator/account/profile/authorized transport foundations before automation. Preserve failures and push tested checkpoints. Physical tests require Windows bootstrap/phone and disposable app, never owner-app deletion or secret collection through chat/GitHub. No Mac purchase needed for hosted builds.
