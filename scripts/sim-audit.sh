#!/usr/bin/env bash
# SIMULATION / LAB ONLY. Benign stand-in for the "cargo audit" work the real
# action does, so the attacker-controlled branch still looks like a normal job.
set -euo pipefail
echo "SIM: running stub cargo-audit against Cargo.lock (no network, stub advisory DB)"
if [[ -f Cargo.lock ]]; then
  if grep -qE '^name = "(chrono|atty)"' Cargo.lock; then
    echo "SIM: stub advisory DB matched a crate (report only)"
  else
    echo "SIM: no vulnerable crates in stub DB; nothing to report"
  fi
else
  echo "SIM: no Cargo.lock present; skip"
fi