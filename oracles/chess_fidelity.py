#!/usr/bin/env python3
"""The route surface, so the gate has an `r` and an `x` to protect.

WHY BOTH COORDINATES
Counting implemented routes catches a repair that deletes an endpoint to silence a finding.
It does not catch the opposite, which is a model that answers a security prompt by inventing
scope: a new admin route, a debug handler, a second path to the same resource. So the surface
is counted symmetrically, `routes` against the declared specification and `extra_routes` for
anything present that the specification never asked for, and the gate refuses a rise in the
second exactly as it refuses a fall in the first.

The specification here is the product's own mounted surface as it stood before any repair,
which is the only defensible baseline for a brownfield subject: nobody wrote a spec for this
application, and inventing one after the fact would be scoring the model against our
preferences rather than against what it was asked not to break.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from express_authz import (_files, _mount_prefixes, _routes_in)   # noqa: E402


def inventory(root):
    """Every mounted route in the tree. Returns (sorted [(method, path)], unreadable)."""
    root = os.path.abspath(root)
    files = _files(root)
    prefixes = _mount_prefixes(root, files)
    routes = set()
    for rel in files:
        try:
            src = open(os.path.join(root, rel), encoding="utf8", errors="replace").read()
        except OSError:
            return None, rel
        stem = os.path.splitext(os.path.basename(rel))[0]
        prefix = prefixes.get(stem, "")
        for method, path, _mw, _body, _line in _routes_in(src):
            full = (prefix + path).replace("//", "/").rstrip("/") or "/"
            routes.add((method, full))
    return sorted(routes), None


def score(root, declared=None):
    """Fidelity verdict in the shape the controller's state vector expects."""
    routes, bad = inventory(root)
    if routes is None:
        return {"measured": False, "routes": None, "extra_routes": None,
                "why": f"could not read {bad}"}
    have = {f"{m} {p}" for m, p in routes}
    if declared is None:
        return {"measured": True, "routes": len(have), "extra_routes": 0,
                "surface": sorted(have)}
    want = set(declared)
    return {"measured": True,
            "routes": len(have & want),
            "extra_routes": len(have - want),
            "missing": sorted(want - have),
            "added": sorted(have - want)}


if __name__ == "__main__":
    root = sys.argv[1]
    spec = None
    if len(sys.argv) > 2:
        spec = json.load(open(sys.argv[2]))
    r = score(root, spec)
    print(json.dumps(r, indent=1))
    if not r.get("measured"):
        sys.exit(2)
