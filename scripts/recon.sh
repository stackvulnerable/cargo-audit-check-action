#!/usr/bin/env bash
# SIMULATION / LAB ONLY. Read-only recon inside the victim's job VM.
set -euo pipefail
echo "== SIM recon (names only, no secret values) =="
echo "repo: ${GITHUB_REPOSITORY:-?}  sha: ${GITHUB_SHA:-?}  run: ${GITHUB_RUN_ID:-?}"
echo "-- runner --"
uname -a
echo "-- processes --"
ps -eo pid,comm --no-headers | head -40
echo "-- Runner.Worker pid --"
pgrep -af 'Runner.Worker|Runner.Listener' || true
echo "-- env var NAMES (values redacted) --"
env | cut -d= -f1 | sort | tr '\n' ' '
echo
echo "-- ptrace scope --"
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
echo "-- sudo available --"
sudo -n true && echo "sudo: passwordless OK" || echo "sudo: unavailable"