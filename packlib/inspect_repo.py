#!/usr/bin/env python3
"""What would the harness read in this repository, and what can nothing read?

This is the question to ask BEFORE any scan, and it is the one nobody asks. Running it on
the dealership subject the first time turned up two blind spots in a repository that had
already been through three generations of oracle work: three container files that no lane
opens, and `init-db.sql` — the script that creates the database, grants its privileges and
inserts the first administrator — which at that point no runtime even claimed.

    python -m packlib.inspect_repo <profile> <repo>
    python -m packlib.inspect_repo dealership car_dealership-experiment/car_dealership_original_code

The same function backs the MCP tool, so an agent asking "what am I working on?" gets the
routing and the blind spots in one answer rather than discovering them per file.
"""
import json
import os
import sys

from .loader import load_policy


def inspect(profile, root):
    """Routing + coverage for one repository. Serialisable, for the MCP surface."""
    P = load_policy(profile, root=root)
    inv = P.inventory
    runtimes = {}
    for rt, files in sorted(inv.by_runtime.items()):
        lanes = P.lanes_by_runtime().get(rt, [])
        runtimes[rt] = {
            "files": len(files),
            "read": bool(lanes),
            "lanes": lanes,
            "packs": [p.id for p in P.packs if p.runtime == rt],
            "examples": files[:5],
        }
    return {
        "profile": P.profile,
        "manifest": P.manifest_hash,
        "runtimes": runtimes,
        # The two honest-blind-spot categories, kept separate because they need different
        # answers: `unread` means "we know what language this is and have written no rules
        # for it"; `unclaimed` means "no runtime pack even recognises this".
        "unread": {rt: len(fs) for rt, fs in inv.unread.items()},
        "unclaimed": inv.unclaimed,
        "excluded": len(inv.skipped),
        "rules": len(P.rules),
        "suppressed": P.suppressed,
        "deployment": P.deployment,
    }


def guidance(profile, root, path):
    """The rules that apply to ONE module, because of the language it is written in.

    This is the polyglot ask: a `.py` module gets the Python packs, a `.html` module gets
    the browser packs, and both get the general vocabulary, the org standards and the
    project's own facts. Coherence comes from the shared layers — the same `public_routes`
    answers both lanes — while the detectors differ.
    """
    from . import detect as _detect
    P = load_policy(profile, root=root)
    detectors = {p.runtime: p.detect for p in P.packs if p.runtime and p.detect}
    # Runtime packs that this profile did NOT load still get to claim a file, so an
    # unhandled language is reported as unread rather than silently answered with nothing.
    from .loader import _all_runtime_packs
    for rt, p in _all_runtime_packs().items():
        detectors.setdefault(rt, p.detect)
    hits = _detect.claim(os.path.join(root, path) if not os.path.isabs(path) else path,
                         detectors)
    if not hits:
        return {"path": path, "runtime": None,
                "advice": "No runtime pack claims this file. It is a blind spot, not a "
                          "clean result — either add a runtime pack that claims it, or "
                          "record that nothing reads it."}
    rt = hits[0]
    view = P.for_runtime(rt)
    lanes = P.lanes_by_runtime().get(rt, [])
    return {
        "path": path,
        "runtime": rt,
        "read": bool(lanes),
        "lanes": lanes,
        "packs": [{"id": p.id, "tier": p.tier} for p in view.packs],
        # A suppressed rule is marked HERE, in the rule the agent reads, not only in a
        # sibling list it may not look at. Suppression is a decision someone signed; the
        # agent should see the signature next to the rule, and see that the rule still
        # exists -- it was stood down, not deleted.
        "rules": {rid: {"sev": r["sev"], "remedy": r.get("remedy"),
                        "attack": r.get("attack"), "failure": r.get("failure"),
                        "overreach": r.get("overreach"),
                        "suppressed_by": next((x["by"] for x in view.suppressed
                                               if x["rule"] == rid), None)}
                  for rid, r in view.rules.items()},
        "facts": {k: sorted(v) if isinstance(v, (list, set, frozenset)) else v
                  for k, v in view._facts.items()},
        "deployment": view.deployment,
        "suppressed": view.suppressed,
    }


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    profile, root = argv[1], argv[2]
    if len(argv) > 3:
        print(json.dumps(guidance(profile, root, argv[3]), indent=2)[:4000])
        return 0
    P = load_policy(profile, root=root)
    print(f"profile {P.profile}   manifest {P.manifest_hash}   {len(P.rules)} rules   "
          f"{len(P.suppressed)} suppressed")
    print(f"deployment: {P.deployment or '(undeclared)'}")
    print("\nwhat is in this repository:")
    print(P.inventory.report())
    print("\nlanes that will run:")
    for rt, lanes in sorted(P.lanes_by_runtime().items()):
        print(f"  {rt:<12} {', '.join(lanes)}")
    if P.inventory.unread:
        print("\nBLIND SPOTS — files a declared runtime claims but no lane reads:")
        for rt, fs in sorted(P.inventory.unread.items()):
            print(f"  {rt:<12} {len(fs)} file(s): {', '.join(fs[:4])}")
        print("  These are UNREAD, not clean. A zero from this profile says nothing "
              "about them.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
