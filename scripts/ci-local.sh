#!/usr/bin/env bash
# Runs the same checks as .github/workflows/ci.yml. Run before pushing.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
echo "ci-local: all checks passed"
