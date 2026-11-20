#!/usr/bin/env bash
# SIMULATION / LAB ONLY. Demonstrates, with ONLY the installation token the
# victim workflow passed to this action, what the attacker can reach in the
# victim repo: identity of the token, its permission set, repo visibility of
# the installation, CI runs, and repo contents. Read-only calls; no secrets
# are printed.
set -euo pipefail
REPO="${GITHUB_REPOSITORY:?}"
API="https://api.github.com"
H1="Authorization: Bearer ${SIM_TOKEN}"
H2="Accept: application/vnd.github+json"
H3="X-GitHub-Api-Version: 2022-11-28"

get() { curl -sS -o /tmp/sim_prim.json -w '%{http_code}' -H "$H1" -H "$H2" -H "$H3" "$1"; }
show() { echo "SIM: $1"; }

show "== token identity (GET /installation) =="
CODE=$(get "$API/installation")
echo "  HTTP ${CODE}"
[ "$CODE" = "200" ] && jq -c '{id, app: .app.slug, account: .account.login, permissions}' /tmp/sim_prim.json || true

show "== repositories visible to this installation =="
CODE=$(get "$API/installation/repositories?per_page=10")
echo "  HTTP ${CODE}"
[ "$CODE" = "200" ] && jq -r '.repositories[] | "  \(.full_name) (private=\(.private))"' /tmp/sim_prim.json || true

show "== victim repo object incl. token's permissions (GET /repos/$REPO) =="
CODE=$(get "$API/repos/$REPO")
echo "  HTTP ${CODE}"
[ "$CODE" = "200" ] && jq -c '{full_name, private, default_branch, permissions}' /tmp/sim_prim.json || true

show "== CI runs readable (actions:read) =="
CODE=$(get "$API/repos/$REPO/actions/runs?per_page=5")
echo "  HTTP ${CODE}"
[ "$CODE" = "200" ] && jq -r '.workflow_runs[] | "  run \(.id) \(.name) \(.status)/\(.conclusion // "-")"' /tmp/sim_prim.json || true

show "== release config readable (contents:read) =="
CODE=$(get "$API/repos/$REPO/contents/.github/workflows/release.yml")
echo "  HTTP ${CODE}"
[ "$CODE" = "200" ] && jq -r '"  release.yml present, \(.size) bytes"' /tmp/sim_prim.json || true

show "== recent commits readable =="
CODE=$(get "$API/repos/$REPO/commits?per_page=5")
echo "  HTTP ${CODE}"
[ "$CODE" = "200" ] && jq -r '.[] | "  \(.sha[0:10]) \(.commit.message | split("\n")[0])"' /tmp/sim_prim.json || true

show "== issues reach (stand-in app has no issues perm; real one had issues:write) =="
CODE=$(get "$API/repos/$REPO/issues?per_page=1")
echo "  HTTP ${CODE} (403 = expected here)"

show "== SIM primitives demo done =="