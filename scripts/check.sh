#!/usr/bin/env bash
# Single Source of Truth Quality Gate for Claude Shield (Local + CI + Release)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "🌱 [1/4] Running AI-Native Garden guardrails..."
python3 "${REPO_ROOT}/scripts/garden-guard.py"

echo "🦀 [2/4] Running Rust clippy (-D warnings)..."
cargo clippy --manifest-path "${REPO_ROOT}/core/Cargo.toml" --all-targets --quiet -- -D warnings

echo "🧪 [3/4] Running Rust test suite..."
cargo test --manifest-path "${REPO_ROOT}/core/Cargo.toml" --quiet

echo "🦅 [4/4] Typechecking native macOS SwiftUI app..."
if [[ "$(uname -s)" == "Darwin" ]]; then
  ARCH="$(uname -m)"
  swiftc -typecheck -target "${ARCH}-apple-macos13.0" \
    -framework Cocoa -framework SwiftUI -framework Network -framework QuartzCore \
    "${REPO_ROOT}/app/ClaudeShieldApp.swift"
else
  echo "ERROR: macOS (swiftc) is required to verify app/ClaudeShieldApp.swift" >&2
  exit 1
fi

echo "✅ All Claude Shield quality gates passed."
