#!/usr/bin/env bash
# Runs the same checks as .github/workflows/ci.yml. Run before pushing.
# Needs the tpm2-tss development files (pkg-config tss2-esys) and swtpm for the TPM tests.
set -euo pipefail
cd "$(dirname "$0")/.."
if ! pkg-config --exists tss2-esys; then
  echo "ci-local: pkg-config cannot find tss2-esys (install libtss2-dev or set PKG_CONFIG_PATH)" >&2
  exit 1
fi
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy -p torngatd --no-default-features --locked -- -D warnings
eval "$(scripts/swtpm.sh start)"
trap 'scripts/swtpm.sh stop' EXIT
cargo test --workspace --all-features --locked
cargo deny check
echo "ci-local: all checks passed"
