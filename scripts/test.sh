#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/fixtures.py
swift test
swift run omnisign-inspect Tests/OmniCoreTests/Fixtures/valid.ipa >/dev/null
if swift run omnisign-inspect Tests/OmniCoreTests/Fixtures/traversal.ipa; then
    echo 'ERROR: hostile archive accepted' >&2
    exit 1
fi
