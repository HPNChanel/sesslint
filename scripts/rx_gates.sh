#!/usr/bin/env bash
# RX-P1.2a: read-only gate for the rust/ workspace.
# Order: cargo fmt --check, cargo clippy -D warnings, cargo test --release.
# Scope is one package (--crate NAME or a single positional name) or every
# workspace package (no args, or --all). The first non-zero gate stops the run.
# cargo fmt is only invoked with --check, and clippy is never passed --fix.

set -u

usage() {
  echo "usage: scripts/rx_gates.sh [--all | --crate NAME | NAME]" >&2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

scope="all"
crate=""
seen_all=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      seen_all=1
      shift
      ;;
    --crate|-p)
      if [[ $# -lt 2 ]]; then
        echo "rx-gates: --crate requires a package name" >&2
        usage
        exit 2
      fi
      if [[ -n "$crate" ]]; then
        echo "rx-gates: only one crate is accepted" >&2
        exit 2
      fi
      crate="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "rx-gates: unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      if [[ -n "$crate" ]]; then
        echo "rx-gates: only one crate is accepted" >&2
        exit 2
      fi
      crate="$1"
      shift
      ;;
  esac
done

if [[ "$seen_all" -eq 1 && -n "$crate" ]]; then
  echo "rx-gates: --all cannot be combined with a crate name" >&2
  exit 2
fi

if [[ -n "$crate" ]]; then
  scope="one"
  case "$crate" in
    -* | */* | *\\* | *..*)
      echo "rx-gates: invalid crate name" >&2
      exit 2
      ;;
  esac
fi

cd "${ROOT}/rust" || {
  echo "rx-gates: cannot enter rust/" >&2
  exit 2
}

if [[ ! -f Cargo.toml ]]; then
  echo "rx-gates: missing rust/Cargo.toml" >&2
  exit 2
fi

export CARGO_TERM_COLOR=never

if [[ "$scope" == "one" ]]; then
  scope_label="$crate"
  fmt_args=(--package "$crate")
  pkg_args=(--package "$crate")
else
  scope_label="all"
  fmt_args=(--all)
  pkg_args=(--workspace)
fi

echo "rx-gates: scope=${scope_label} manifest=rust/Cargo.toml"

echo "rx-gates: fmt: cargo fmt --manifest-path Cargo.toml ${fmt_args[*]} --check"
command cargo fmt --manifest-path Cargo.toml "${fmt_args[@]}" --check
fmt_rc=$?
if [[ "$fmt_rc" -ne 0 ]]; then
  echo "rx-gates: summary scope=${scope_label} fmt=${fmt_rc} clippy=skipped test=skipped"
  exit "$fmt_rc"
fi

echo "rx-gates: clippy: cargo clippy --manifest-path Cargo.toml ${pkg_args[*]} -- -D warnings"
command cargo clippy --manifest-path Cargo.toml "${pkg_args[@]}" -- -D warnings
clippy_rc=$?
if [[ "$clippy_rc" -ne 0 ]]; then
  echo "rx-gates: summary scope=${scope_label} fmt=0 clippy=${clippy_rc} test=skipped"
  exit "$clippy_rc"
fi

echo "rx-gates: test: cargo test --manifest-path Cargo.toml ${pkg_args[*]} --release"
command cargo test --manifest-path Cargo.toml "${pkg_args[@]}" --release
test_rc=$?
if [[ "$test_rc" -ne 0 ]]; then
  echo "rx-gates: summary scope=${scope_label} fmt=0 clippy=0 test=${test_rc}"
  exit "$test_rc"
fi

echo "rx-gates: summary scope=${scope_label} fmt=0 clippy=0 test=0"
exit 0
