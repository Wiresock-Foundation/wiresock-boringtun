#!/usr/bin/env python3
# Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""Check source and distribution attribution without claiming unverified dates."""
import hashlib
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNER = "Vadim Smirnov (doing business as WireSock)"
MARKER = b"\nWireSock fork additions\n"

def check():
    # Git for Windows may use CRLF in a worktree; compare canonical Git text.
    license_bytes = (ROOT / "LICENSE.md").read_bytes().replace(b"\r\n", b"\n")
    upstream, separator, fork = license_bytes.partition(MARKER)
    expected = "6dbef24708bad8c727bd80cca58ba8aa1637cdcb2cc6e9a31ea49235717e9391"
    if hashlib.sha256(upstream).hexdigest() != expected:
        raise ValueError("Cloudflare's original license changed")
    if not separator:
        raise ValueError("LICENSE.md omits the fork's distribution notice")
    if f"Copyright (c) 2024-2026 {OWNER}. All rights reserved.".encode() not in fork:
        raise ValueError("fork owner/range missing")
    if upstream.split(b"\n", 1)[1].strip() not in fork:
        raise ValueError("fork BSD terms incomplete")
    tracked = subprocess.check_output(["git", "-C", str(ROOT), "ls-files"], text=True).splitlines()
    count = 0
    for name in tracked:
        path = ROOT / name
        if path.suffix not in {".rs", ".java", ".cpp", ".c"}:
            continue
        contents = path.read_text(encoding="utf-8")
        if re.search(r"Copyright \(c\) [0-9-]+ WireSock\. All rights reserved\.", contents):
            raise ValueError(f"trade-name-only notice: {name}")
        if re.search(r"Copyright \(c\) [0-9-]+ " + re.escape(OWNER), contents):
            count += 1
    if count < 39:
        raise ValueError("fork source notices unexpectedly missing")
    print(f"Attribution checks passed ({count} files); existing year ranges are preserved, not independently verified.")

if __name__ == "__main__":
    check()
