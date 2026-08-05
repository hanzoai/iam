#!/usr/bin/env python3
"""Run this repo's mutation table (scripts/mutants.py) and score it STRICTLY.

    scripts/mutate.py [name-substring-filter]

A mutant is KILLED only if all four hold: the anchor is found EXACTLY once, the
tree still COMPILES with the mutation applied, the named -run pattern matches at
least one test, and that test then FAILS. Anything else — anchor drift, a mutant
that does not build, a -run that matches nothing, a test that still passes — is a
hard FAILURE and is never counted as a kill.

That strictness is the whole point. A lenient runner scores an anchor that no
longer exists as a kill and reports a suite that tests nothing as green, which is
worse than no score at all: it is a false one. The BASELINE pass up front exists
for the same reason — if a named test does not pass and match on the pristine
tree, its "kill" below would be measuring the wrong thing.

Every mutation is reverted in a finally block, including on interrupt. Run it on
a clean tree: `git status --short` should be empty before and after.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / "scripts" / "mutants.py"
ONLY = sys.argv[1] if len(sys.argv) > 1 else ""

ns = {}
exec(compile(TABLE.read_text(), str(TABLE), "exec"), ns)
MUTANTS = [m for m in ns["MUTANTS"] if ONLY in m[0]]
if not MUTANTS:
    sys.exit(f"no mutant matches {ONLY!r}")

env = dict(os.environ, PATH="/usr/local/go/bin:" + os.environ["PATH"])


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)


def matched(result):
    """How many tests the -run pattern actually reached."""
    return len(re.findall(r"^=== RUN", result.stdout, re.M))


print("== baseline ==")
baseline_ok = True
for name, _edits, test, pkg in MUTANTS:
    r = run(["go", "test", pkg, "-run", "^(" + test + ")$", "-count=1", "-v"])
    ok = r.returncode == 0 and matched(r) > 0
    baseline_ok &= ok
    print(f"  {'ok  ' if ok else 'FAIL'} {test:<62} matched={matched(r)}")
if not baseline_ok:
    print("BASELINE BROKEN — every score below is meaningless")

print("\n== mutants ==")
killed = failed = 0
for name, edits, test, pkg in MUTANTS:
    originals = {}
    drift = None
    for path, old, new in edits:
        p = ROOT / path
        src = p.read_text()
        originals[p] = src
        n = src.count(old)
        if n != 1:
            drift = f"anchor occurs {n}x in {path}"
            break
        p.write_text(src.replace(old, new, 1))
    try:
        if drift:
            print(f"  FAIL  {name}\n        ANCHOR DRIFT: {drift}")
            failed += 1
            continue
        b = run(["go", "build", "./..."])
        if b.returncode != 0:
            head = b.stderr.strip().splitlines()[:2]
            print(f"  FAIL  {name}\n        NO-COMPILE: {head}")
            failed += 1
            continue
        r = run(["go", "test", pkg, "-run", "^(" + test + ")$", "-count=1", "-v"])
        if matched(r) == 0:
            print(f"  FAIL  {name}\n        -run '{test}' MATCHED NOTHING")
            failed += 1
        elif r.returncode != 0:
            print(f"  KILL  {name}  ({test})")
            killed += 1
        else:
            print(f"  FAIL  {name}\n        SURVIVED: {test} still passes")
            failed += 1
    finally:
        for p, src in originals.items():
            p.write_text(src)

print(f"\nscore: {killed}/{len(MUTANTS)} killed, {failed} failed")
sys.exit(0 if killed == len(MUTANTS) and baseline_ok else 1)
