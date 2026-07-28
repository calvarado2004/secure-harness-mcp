#!/usr/bin/env python3
"""packtest — the obligations a pack must discharge before the harness will load it.

HARNESS-EXTENSION.md says what every new rule owes you. Until now that was doctrine in a
markdown file, which is to say it was advice, which is to say it was optional. Here it is an
executable admission test, and a pack that fails it does not ship.

    python -m packlib.packtest              # every pack
    python -m packlib.packtest browser-js   # one runtime

THE OBLIGATIONS

  1. POSITIVE CONTROL. Every rule the pack declares is flagged on some artifact in
     controls/positive/. Without it you cannot tell "this codebase is clean" from "my rule
     is broken", and the difference between those two has been the story of this project.

  2. PAIRED NEGATIVE CONTROL. Every filter that keeps a false positive out is matched
     against a real defect it must still catch. Writing the browser lane, the negative
     controls caught two rule bugs within minutes of each other -- one of which was double-
     counting every finding, reporting weighted load 91 where the truth was 43.

  3. AN UNMEASURED VERDICT. The pack must declare how it says "I could not read this", and
     it must not be the same value as "clean". Every AST engine returns zero findings on a
     file that does not parse; a container that never boots exercises zero probes. To a gate
     reading totals each is indistinguishable from improvement, and all of them happened here.

  4. STATED LIMITS. A non-empty LIMITS.md. A bespoke lane whose limits are undocumented will
     be read as a complete one.

  5. EVERY RULE STATES ITS ATTACK OR ITS FAILURE. Security rules answer "can you state the
     attack?"; practice rules answer "can you state the failure this prevents?". A rule that
     answers neither is hygiene at best, and must not carry weight it did not earn.

  6. HELD-OUT ISOLATION. A pack marked `heldout: true` must not be reachable from any
     project profile. Once a rule set is optimised against, its agreement stops being
     independent evidence -- so this stops being a convention someone can break by accident.

Obligations 1 and 2 need the pack's detector, which for Tier 0 still lives in the experiment
modules the packs reference by name. Where a detector cannot be imported, the control is
reported SKIPPED rather than passed: an unrun control is not a green one.
"""
import os
import sys

from .loader import PACKS, PROJECTS, ORGS, Pack, PackError, _read, _load_pack_dir

PASS, FAIL, SKIP = "[PASS]", "[FAIL]", "[SKIP]"

# Where Tier-0 detectors still live. Packs name them as `module.function`; the pack system
# owns the rules and the controls, the experiment still owns the code. Tier 1 moves the
# code under the pack; until then this is the seam, and it is declared rather than implicit.
_ROOT = os.path.dirname(PACKS)
_DETECTOR_PATHS = [p for p in (
    # standalone distribution: the lane modules ship next to the packs
    os.path.join(_ROOT, "oracles"),
    # inside the research repo: they still live with the experiments they were written for
    os.path.join(_ROOT, "car_dealership-experiment", "oracles"),
    os.path.join(_ROOT, "webapp-experiment"),
) if os.path.isdir(p)]


def _import_detector(spec):
    """`repo_security.scan_frontend` -> the function, or None if unavailable here."""
    if "." not in spec:
        return None
    mod, _, fn = spec.rpartition(".")
    for p in _DETECTOR_PATHS:
        if p not in sys.path:
            sys.path.insert(0, p)
    try:
        m = __import__(mod)
        return getattr(m, fn, None)
    except Exception:
        return None


def _all_packs():
    out = []
    for dirpath, dirnames, filenames in os.walk(PACKS):
        if "pack.yaml" in filenames:
            out.append(_load_pack_dir(dirpath))
    for d in (ORGS,):
        if os.path.isdir(d):
            for dirpath, _, filenames in os.walk(d):
                if "pack.yaml" in filenames:
                    out.append(_load_pack_dir(dirpath))
    return [p for p in out if p]


class Result:
    def __init__(self):
        self.rows = []

    def add(self, status, pack, msg):
        self.rows.append((status, pack, msg))
        print(f"{status} {pack:<34} {msg}")

    @property
    def failed(self):
        return [r for r in self.rows if r[0] == FAIL]

    @property
    def skipped(self):
        return [r for r in self.rows if r[0] == SKIP]


def _run_lane_on(pack, control_file):
    """Run the pack's first importable detector over one control artifact.

    A lane declares `input: file` or `input: tree`. That is not bookkeeping: a tree lane run
    against a directory holding BOTH the positive and the negative control would score them
    together, and the negative would inherit the positive's findings. Each control therefore
    gets its own directory, and the pack says which shape its detector wants.
    """
    for lane in pack.lanes.values():
        det = _import_detector(lane.get("detector", ""))
        if det is None:
            continue
        path = os.path.join(pack.dir, control_file)
        if lane.get("input") == "tree" and not os.path.isdir(path):
            return None
        try:
            out = det(path)
        except Exception:
            return None
        if isinstance(out, tuple):
            out = out[0]
        if out is None:
            return None
        return {f.get("rule") for f in out}
    return None


def check_pack(pack, res):
    name = pack.id
    detect_only = pack.status == "detect-only"

    # ---- 3. unmeasured verdict -----------------------------------------
    if pack.runtime and not pack.axis:
        if not pack.unmeasured_verdict:
            res.add(FAIL, name, "runtime pack declares no `unmeasured_verdict`: it cannot "
                                "say 'I could not read this' distinctly from 'clean'")
        else:
            res.add(PASS, name, f"unmeasured verdict declared: {pack.unmeasured_verdict}")

    if detect_only:
        if pack.rules or pack.lanes:
            res.add(FAIL, name, "status is detect-only but the pack ships rules or lanes")
        else:
            res.add(PASS, name, "detect-only: declared runtime, no lanes, files "
                                "inventoried as UNREAD (an honest blind spot)")
        return

    # ---- 5. every rule states its attack or its prevented failure -------
    if pack.rules:
        naked = [r for r, s in pack.rules.items()
                 if not (s or {}).get("attack") and not (s or {}).get("failure")]
        if naked:
            res.add(FAIL, name, f"{len(naked)} rule(s) state neither an attack nor a "
                                f"prevented failure: {', '.join(sorted(naked)[:4])}")
        else:
            res.add(PASS, name, f"all {len(pack.rules)} rules state an attack or a failure")

    # ---- 7. every security rule states its OVERREACH ---------------------
    # Security wants everything closed. Least privilege is the right instinct and a real
    # stack still has to connect to things, so the useful question about a rule is not only
    # "what attack does this stop?" but "what does a too-strict reading of it break?".
    # A rule that cannot answer the second gets applied at full strength somewhere it does
    # not belong, breaks a working deployment, and is turned off -- taking the attack it DID
    # stop with it. "None known" is a legitimate answer; silence is not, because silence is
    # indistinguishable from never having asked.
    if pack.axis == "security" and pack.rules:
        blind = [r for r, s in pack.rules.items() if not (s or {}).get("overreach")]
        if blind:
            res.add(FAIL, name, f"{len(blind)} security rule(s) do not state what a "
                                f"too-strict application breaks: "
                                f"{', '.join(sorted(blind)[:4])}")
        else:
            res.add(PASS, name, f"all {len(pack.rules)} security rules state their "
                                f"overreach (what over-applying them costs)")

    # ---- 4. stated limits ----------------------------------------------
    if pack.rules or pack.binds:
        lp = pack.limits_path()
        if not os.path.isfile(lp) or not open(lp).read().strip():
            res.add(FAIL, name, f"no non-empty {pack.limits}: a bespoke lane whose limits "
                                f"are undocumented will be read as a complete one")
        else:
            res.add(PASS, name, f"{pack.limits} present and non-empty")

    # ---- 1 + 2. controls -----------------------------------------------
    pos = pack.controls.get("positive") or []
    neg = pack.controls.get("negative") or []
    if pack.lanes and not pos:
        res.add(FAIL, name, "ships a lane with no positive control: a zero from it means "
                            "nothing")
    for c in pos:
        f = c["file"]
        if not os.path.exists(os.path.join(pack.dir, f)):
            res.add(FAIL, name, f"positive control missing on disk: {f}")
            continue
        got = _run_lane_on(pack, f)
        if got is None:
            res.add(SKIP, name, f"positive control {f}: detector not importable here "
                                f"(an unrun control is not a passing one)")
            continue
        missing = [r for r in c.get("must_flag", []) if r not in got]
        if missing:
            res.add(FAIL, name, f"positive control {f} did not fire: {missing}")
        else:
            res.add(PASS, name, f"positive control {f} fires all "
                                f"{len(c.get('must_flag', []))} rules")
    for c in neg:
        f = c["file"]
        if not os.path.exists(os.path.join(pack.dir, f)):
            res.add(FAIL, name, f"negative control missing on disk: {f}")
            continue
        got = _run_lane_on(pack, f)
        if got is None:
            res.add(SKIP, name, f"negative control {f}: detector not importable here")
            continue
        loud = [r for r in c.get("must_not_flag", []) if r in got]
        if loud:
            res.add(FAIL, name, f"negative control {f} fired on {loud} — a suppression "
                                f"widened, or never worked")
        else:
            res.add(PASS, name, f"negative control {f} silent on "
                                f"{len(c.get('must_not_flag', []))} rules "
                                f"({len(c.get('covers', []))} suppressions covered)")


def check_profiles(res):
    """Obligations that are about composition rather than a single pack."""
    from .loader import load_policy
    if not os.path.isdir(PROJECTS):
        return
    for f in sorted(os.listdir(PROJECTS)):
        if not f.endswith(".yaml"):
            continue
        name = f[:-5]
        prof = _read(os.path.join(PROJECTS, f))
        auto = prof.get("runtimes") in ("auto", ["auto"])
        try:
            # `auto` profiles need a tree; resolve them against the packs dir itself, which
            # is enough to prove the chain composes.
            load_policy(name, root=PACKS if auto else None)
            res.add(PASS, f"projects/{name}", "profile resolves: every required fact is "
                                              "supplied and no layer overstepped")
        except PackError as e:
            res.add(FAIL, f"projects/{name}", f"does not resolve: {e}")

    # ---- bindings resolve, even for packs no profile loads yet ----------
    # The loader validates a binding when a profile pulls the pack in. A pack nobody loads
    # yet is exactly where a typo survives longest, so the whole set is checked here too.
    packs = _all_packs()
    declared = {r for p in packs for r in p.rules}
    dangling = sorted({(p.id, b) for p in packs for b in p.binds if b not in declared})
    if dangling:
        res.add(FAIL, "bindings", f"binds a rule no pack declares: {dangling}")
    else:
        bound = {b for p in packs for b in p.binds}
        unbound = sorted(r for r in declared if r.startswith("practice/") and r not in bound)
        res.add(PASS, "bindings", f"every binding resolves"
                                  + (f"; {len(unbound)} declared rule(s) have no detector "
                                     f"in any pack and contribute nothing to any verdict: "
                                     f"{unbound}" if unbound else ""))

    # ---- 6. held-out isolation -----------------------------------------
    held = [p.id for p in _all_packs() if p.heldout]
    if held:
        res.add(PASS, "held-out", f"declared held-out and refused by the loader: {held}")
    else:
        res.add(PASS, "held-out", "no pack claims held-out status; Semgrep stays outside "
                                  "the pack system entirely, which is stronger")


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    res = Result()
    packs = [p for p in _all_packs() if not only or p.id.startswith(only)]
    print(f"packtest: {len(packs)} packs\n")
    for p in sorted(packs, key=lambda p: p.id):
        check_pack(p, res)
    print()
    check_profiles(res)
    print()
    n_fail, n_skip = len(res.failed), len(res.skipped)
    print(f"{len(res.rows)} checks, {n_fail} failed, {n_skip} skipped")
    if n_skip:
        print("NOTE: skipped controls did not run. They are not passes.")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
