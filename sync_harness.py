#!/usr/bin/env python3
"""Keep the shipped harness identical to the one the experiments actually run.

WHY THIS EXISTS
The research tree runs the lanes; this repository ships them. Two copies of an instrument is
exactly the failure this project keeps finding in its own measurements: a lane edited in one
place and not the other means the arms silently run different instruments, and the
cross-model comparison stops being a comparison. Neither copy can be deleted, because the
research tree has to stay self-contained for the artifact and this repository has to stay
self-contained for `brew install`. So the copies are kept identical mechanically, and drift
is made loud.

The research tree is CANONICAL. It is where the experiments run and where the paper points.

    python3 sync_harness.py --check     # exit 1 on any drift, print what differs
    python3 sync_harness.py             # copy research tree -> this repository

Run --check in CI and before any release. Run the copy after changing a lane, then commit.
"""
import filecmp
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEST = HERE          # the packs ship at the repo root, beside packlib
SRC = os.environ.get(
    "SECURE_HARNESS_RESEARCH_TREE",
    os.path.join(os.path.dirname(HERE), "secure-harness-paper", "evidence"))

# Whole directories that ship verbatim.
TREES = ["packs", "packlib", "projects", "orgs"]
# Individual lane detectors. The research tree's oracles/ also holds experiment glue
# (the pipeline driver, the exploitation battery, the scorers) which is NOT shipped: this
# repository distributes the instruments, not the study that used them.
LANES = {
    "oracles/flask_authz.py": "oracles/flask_authz.py",
    "oracles/repo_secrets.py": "oracles/repo_secrets.py",
    "oracles/express_authz.py": "oracles/express_authz.py",
    "oracles/chess_probe.py": "oracles/chess_probe.py",
    "oracles/chess_fidelity.py": "oracles/chess_fidelity.py",
}
for _m in ("repo_authz", "repo_compose", "repo_fastapi", "repo_nginx", "repo_practice",
           "repo_security", "repo_seed", "repo_storage"):
    LANES[f"car_dealership-experiment/oracles/{_m}.py"] = f"oracles/{_m}.py"

SKIP = {"__pycache__", ".git", ".DS_Store"}


def _files(root):
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fn in filenames:
            if fn in SKIP or fn.endswith(".pyc"):
                continue
            out.add(os.path.relpath(os.path.join(dirpath, fn), root))
    return out


def check():
    problems = []
    if not os.path.isdir(SRC):
        print(f"research tree not found: {SRC}\n"
              f"set SECURE_HARNESS_RESEARCH_TREE if it lives elsewhere", file=sys.stderr)
        return 2
    for tree in TREES:
        s, d = os.path.join(SRC, tree), os.path.join(DEST, tree)
        if not os.path.isdir(d):
            problems.append(f"{tree}/ missing from the shipped harness")
            continue
        sf, df = _files(s), _files(d)
        for rel in sorted(sf - df):
            problems.append(f"{tree}/{rel} is in the research tree but not shipped")
        for rel in sorted(df - sf):
            problems.append(f"{tree}/{rel} is shipped but not in the research tree")
        for rel in sorted(sf & df):
            if not filecmp.cmp(os.path.join(s, rel), os.path.join(d, rel), shallow=False):
                problems.append(f"{tree}/{rel} DIFFERS")
    for src_rel, dst_rel in sorted(LANES.items()):
        s, d = os.path.join(SRC, src_rel), os.path.join(DEST, dst_rel)
        if not os.path.isfile(s):
            problems.append(f"{src_rel} missing from the research tree")
        elif not os.path.isfile(d):
            problems.append(f"{dst_rel} missing from the shipped harness")
        elif not filecmp.cmp(s, d, shallow=False):
            problems.append(f"{dst_rel} DIFFERS from {src_rel}")
    if problems:
        print(f"DRIFT: {len(problems)} difference(s) between the research tree and the "
              f"shipped harness", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("\nrun `python3 sync_harness.py` to make the shipped copy match, then commit.",
              file=sys.stderr)
        return 1
    print(f"in sync: {len(TREES)} trees and {len(LANES)} lane detectors are identical")
    return 0


def sync():
    for tree in TREES:
        s, d = os.path.join(SRC, tree), os.path.join(DEST, tree)
        if os.path.isdir(d):
            shutil.rmtree(d)
        shutil.copytree(s, d, ignore=shutil.ignore_patterns(*SKIP, "*.pyc"))
        print(f"  {tree}/")
    os.makedirs(os.path.join(DEST, "oracles"), exist_ok=True)
    for src_rel, dst_rel in sorted(LANES.items()):
        shutil.copy2(os.path.join(SRC, src_rel), os.path.join(DEST, dst_rel))
        print(f"  {dst_rel}")
    print("synced. now run: cd harness && python3 -m packlib.packtest")
    return 0


if __name__ == "__main__":
    sys.exit(check() if "--check" in sys.argv else sync())
