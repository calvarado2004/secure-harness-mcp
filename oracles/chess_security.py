#!/usr/bin/env python3
"""Aggregate the chess subject's security lanes into one verdict.

Every lane this study needed already exists; this file only composes them the way
`repo_security.assess_repo` composes the dealership's, so the controller consumes one dict
with a weighted total, an analyzability flag, and a per-lane ran/did-not-run map. The
composition is where measurability lives: a single lane that fails silently drops its whole
rule class, the total falls, and to a gate reading totals that reads as progress. So a lane
that raises is recorded as UNMEASURED for the run rather than contributing zero.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "car_dealership-experiment", "oracles"))

from express_authz import scan_express_authz          # noqa: E402
from repo_secrets import scan_secrets                  # noqa: E402
import repo_compose                                    # noqa: E402
import repo_nginx                                      # noqa: E402
import repo_seed                                       # noqa: E402

SEV_W = {"HIGH": 3, "ERROR": 3, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 1}


def _sql_files(root):
    out = []
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in {"node_modules", ".git", "dist", "build"}]
        out += [os.path.join(dp, f) for f in fns if f.endswith(".sql")]
    return out


def assess_repo(root, backend=None):
    """Security verdict over the chess repository. Same shape as repo_security.assess_repo.

    An ADVISORY finding (a route the project never classified) is reported but excluded from
    the weighted load, exactly as it is in the single-file oracle: it reaches the model and
    the reviewer and never drives repair.
    """
    root = os.path.abspath(root)
    backend = backend or os.path.join(root, "backend")
    lanes, gated, advisory = {}, [], []

    def run(name, fn):
        try:
            f, bad = fn()
        except Exception as e:                # a lane that raises is not a lane that is clean
            lanes[name] = False
            return f"{name}: {type(e).__name__}: {str(e)[:80]}"
        if f is None:                         # the lane's own "I could not read this"
            lanes[name] = False
            return f"{name}: unreadable ({bad})"
        lanes[name] = True
        for x in f:
            (advisory if x.get("advisory") else gated).append(x)
        return None

    unread = []
    for name, fn in [
        ("express_authz", lambda: scan_express_authz(backend)),
        ("secrets", lambda: scan_secrets(root)),
        ("compose", lambda: repo_compose.scan_tree(root)),
        ("nginx", lambda: repo_nginx.scan_tree(root)),
    ]:
        u = run(name, fn)
        if u:
            unread.append(u)
    # SQL seed files, each read on its own; a bad one is unread, not clean.
    lanes["seed_sql"] = True
    for s in _sql_files(root):
        f, bad = repo_seed.scan_sql(s)
        if f is None:
            lanes["seed_sql"] = False
            unread.append(f"seed_sql: unreadable ({bad})")
        else:
            gated += f

    weighted = sum(SEV_W.get(x.get("sev", "LOW"), 1) for x in gated)
    return {
        "findings": gated, "advisory": advisory, "weighted": weighted,
        "analyzable": True,               # text lanes do not parse-fail the way an AST does
        "lanes": lanes,
        "lanes_ran": not unread,
        "unread": unread,
    }


if __name__ == "__main__":
    r = assess_repo(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/chess-project"))
    print(f"weighted {r['weighted']}  gated {len(r['findings'])}  advisory {len(r['advisory'])}  "
          f"lanes_ran {r['lanes_ran']}")
    for x in r["findings"]:
        print(f"  [{x['sev']:6s}] {x['rule']:38s} {x.get('file','')}:{x.get('line','')}")
    for x in r["advisory"]:
        print(f"  (adv)  {x['rule']:38s} {x.get('file','')}:{x.get('line','')}")
    if r["unread"]:
        print("UNREAD:", "; ".join(r["unread"]))
