#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift build --package-path Experimental/OfflineSignerLab --jobs 2
lab_bin_dir="$(swift build --package-path Experimental/OfflineSignerLab --show-bin-path)"
python3 scripts/signing_lab.py "$lab_bin_dir/omnisign-lab"
