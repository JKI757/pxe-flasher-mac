#!/usr/bin/env bash
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "go not found" >&2
  exit 1
fi

mod_flag=()
if [ -d vendor ] && [[ "${GOFLAGS:-}" != *"-mod="* ]]; then
  mod_flag=(-mod=mod)
fi

go list "${mod_flag[@]}" -m -json all | python3 - <<'PY'
import json
import os
import re
import sys
from glob import glob

allowed = [
    re.compile(r"MIT License", re.I),
    re.compile(r"BSD", re.I),
    re.compile(r"Apache License", re.I),
    re.compile(r"ISC License", re.I),
    re.compile(r"Public Domain", re.I),
    re.compile(r"CC0", re.I),
]
forbidden = [
    re.compile(r"AGPL", re.I),
    re.compile(r"LGPL", re.I),
    re.compile(r"GPL", re.I),
]

unknown = []
blocked = []

modules = json.JSONDecoder()

def decode_stream(data):
    idx = 0
    while idx < len(data):
        data = data[idx:].lstrip()
        if not data:
            return
        obj, offset = modules.raw_decode(data)
        yield obj
        idx = offset

raw = sys.stdin.read()
for mod in decode_stream(raw):
    if mod.get("Main"):
        continue
    mod_dir = mod.get("Dir")
    mod_path = mod.get("Path")
    if not mod_dir or not os.path.isdir(mod_dir):
        unknown.append((mod_path, "missing module dir"))
        continue

    license_files = []
    for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
        license_files.extend(glob(os.path.join(mod_dir, pattern)))
    if not license_files:
        unknown.append((mod_path, "no license file"))
        continue

    content = ""
    for path in license_files:
        try:
            with open(path, "r", errors="ignore") as f:
                content += f.read() + "\n"
        except OSError:
            continue

    if any(p.search(content) for p in forbidden):
        blocked.append((mod_path, "forbidden license"))
        continue
    if not any(p.search(content) for p in allowed):
        unknown.append((mod_path, "unknown license"))

if blocked:
    print("Blocked licenses:")
    for name, reason in blocked:
        print(f"  - {name}: {reason}")

if unknown:
    print("Unknown licenses:")
    for name, reason in unknown:
        print(f"  - {name}: {reason}")

if blocked or unknown:
    sys.exit(1)
print("All dependency licenses allowed.")
PY
