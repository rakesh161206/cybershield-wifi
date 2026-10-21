#!/usr/bin/env python3
"""Stage selected hunks of a file's diff into the index.

Usage:
    python3 tools/stage_hunks.py <file> --match <regex> [--match <regex> ...]

A hunk is staged when it contains at least one added line matching any
of the given regular expressions. Hunk contents are matched, not indices,
so the selection stays correct as the diff shifts.

Used to keep commit history readable when one file carries several
independent changes.
"""
import re
import subprocess
import sys


def split_hunks(text):
    """Split a unified diff into (header, hunks) where each hunk keeps its
    @@ line and body."""
    lines = text.splitlines(keepends=True)
    header, hunks, current = [], [], None
    for line in lines:
        if line.startswith("@@"):
            if current:
                hunks.append(current)
            current = [line]
        elif current is None:
            header.append(line)
        else:
            current.append(line)
    if current:
        hunks.append(current)
    return header, hunks


def main():
    argv = sys.argv[1:]
    if len(argv) < 2 or "--match" not in argv:
        print(__doc__)
        return 2
    path = argv[0]
    patterns = [argv[i + 1] for i, a in enumerate(argv) if a == "--match"]
    if not patterns:
        print("need at least one --match")
        return 2

    diff = subprocess.run(["git", "diff", "-U3", "--", path],
                          capture_output=True, text=True, check=True).stdout
    header, hunks = split_hunks(diff)
    if not hunks:
        print(f"no diff for {path}")
        return 1

    selected = []
    for hunk in hunks:
        added = [l for l in hunk if l.startswith("+") and not l.startswith("+++")]
        if any(re.search(p, l) for p in patterns for l in added):
            selected.append(hunk)

    if not selected:
        print(f"no hunks of {path} matched {patterns}")
        return 1

    patch = "".join(header) + "".join("".join(h) for h in selected)
    proc = subprocess.run(["git", "apply", "--cached", "-"], input=patch,
                          text=True, capture_output=True)
    if proc.returncode != 0:
        print(proc.stderr)
        return 1
    print(f"staged {len(selected)}/{len(hunks)} hunk(s) of {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
