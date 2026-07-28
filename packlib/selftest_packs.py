#!/usr/bin/env python3
"""Controls for the pack system itself.

TWO KINDS OF CONTROL, AND THE FIRST KIND IS THE WHOLE POINT OF TIER 0.

(A) EQUIVALENCE. Extracting rules out of Python modules into pack files is only safe if the
    extraction changed nothing. Every constant that moved is compared against the module it
    came from, so a typo in a YAML file cannot silently alter a published number. This is the
    same discipline that validated the first parametrisation pass, and it is the reason this
    refactor can be done before the paper rather than after it.

(B) MERGE SEMANTICS. The layering rules are the formal content of the design, so they get
    adversarial controls rather than a docstring: a layer that tries to delete a rule must be
    refused, a suppression without a justification must be refused, and a suppression WITH one
    must still leave the rule visible in the state. If any of these stops holding, an overlay
    becomes a legal way to make the harness promise more while measuring less.

    python -m packlib.selftest_packs
"""
import os
import shutil
import sys
import tempfile

from . import loader
from .loader import PackError, load_policy

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.dirname(HERE)
# The lane modules live next to the packs in the standalone distribution and with the
# experiments inside the research repo. Both layouts are supported explicitly, so a control
# never silently tests a different tree than the one it thinks it is testing.
for _p in (os.path.join(EV, "oracles"),
           os.path.join(EV, "car_dealership-experiment", "oracles"),
           os.path.join(EV, "webapp-experiment")):
    if os.path.isdir(_p):
        sys.path.insert(0, _p)

# Some controls compare a pack against the PRE-PACK source it was extracted from. Those
# files exist only in the research repo. Where they are absent the control is reported
# SKIPPED, never silently passed -- an unrun control is not a green one, and that rule is
# the whole reason this file exists.
LEGACY_POLICY = os.path.join(EV, "webapp-experiment", "policy", "python-web.yaml")
LEGACY_TASK = os.path.join(EV, "webapp-experiment", "tasks", "notes-api.yaml")
SUBJECT = os.path.join(EV, "car_dealership-experiment", "car_dealership_original_code")
_skipped = []


def skip(label, why):
    _skipped.append(label)
    print(f"[SKIP] {label}  ({why})")

_ok = True


def check(label, cond, detail=""):
    global _ok
    _ok = _ok and bool(cond)
    print(("[PASS] " if cond else "[FAIL] ") + label + (f"  {detail}" if detail else ""))


def expect_refused(label, fn, must_mention=None):
    """A control that passes only when the loader REFUSES something."""
    try:
        fn()
    except PackError as e:
        if must_mention and must_mention not in str(e):
            check(label, False, f"refused, but the message never mentions "
                                f"'{must_mention}': {e}")
        else:
            check(label, True, "refused, with a message that says why")
        return
    except Exception as e:                                    # pragma: no cover
        check(label, False, f"raised {type(e).__name__} instead of PackError: {e}")
        return
    check(label, False, "ACCEPTED — the contract does not hold")


# ---------------------------------------------------------------------------
# (A) EQUIVALENCE with the modules the packs were extracted from
# ---------------------------------------------------------------------------
def equivalence():
    print("\n-- (A) equivalence: nothing changed when the rules moved into packs --")
    P = load_policy("dealership",
                    root=SUBJECT if os.path.isdir(SUBJECT) else loader.PACKS)

    import repo_authz
    import repo_practice
    import repo_security

    check("project facts == repo_authz.AUTH_DEPS",
          P.fact("auth_deps") == frozenset(repo_authz.AUTH_DEPS))
    check("project facts == repo_authz.PUBLIC_ROUTES",
          P.fact("public_routes") == frozenset(repo_authz.PUBLIC_ROUTES))
    check("project facts == repo_authz.SENSITIVE",
          P.fact("sensitive_models") == frozenset(repo_authz.SENSITIVE))
    check("project facts == repo_authz.LOCAL_STACK_CREDS",
          P.fact("local_stack_creds") == frozenset(repo_authz.LOCAL_STACK_CREDS))
    check("the practice lane sees the SAME facts as the authz lane",
          frozenset(repo_practice.AUTH_DEPS) == frozenset(repo_authz.AUTH_DEPS)
          and P.fact("sensitive_models") == frozenset(repo_practice.SENSITIVE),
          "one declaration, both lanes — that was the reason to split facts out")

    check("general vocabulary == repo_authz.PRIV_FIELDS",
          P.vocab("priv_fields") == frozenset(repo_authz.PRIV_FIELDS))
    check("general vocabulary == repo_authz.HARD_PRIV",
          P.vocab("hard_priv") == frozenset(repo_authz.HARD_PRIV))
    check("general vocabulary == repo_authz.SECRETISH",
          P.vocab("secretish") == frozenset(repo_authz.SECRETISH))
    check("general vocabulary == repo_authz.ROLE_HINTS",
          P.vocab("role_hints") == frozenset(repo_authz.ROLE_HINTS))
    check("severity scale == repo_security.SEV_W", P.severity == repo_security.SEV_W,
          f"{P.severity}")
    check("skip_dirs == repo_security.SKIP_DIRS",
          set(P.scan["skip_dirs"]) >= set(repo_security.SKIP_DIRS))

    # the webapp side -- only present in the research repo
    import yaml
    if not os.path.isfile(LEGACY_POLICY):
        skip("equivalence with the pre-pack policy/task files",
             "not part of the standalone distribution; run inside the research repo")
        return
    legacy = yaml.safe_load(open(LEGACY_POLICY))
    mine = {r: s["remedy"] for r, s in
            loader._read(os.path.join(loader.PACKS, "python", "security", "commodity",
                                      "pack.yaml"))["rules"].items()}
    check("all 25 python remedies byte-identical to policy/python-web.yaml",
          mine == legacy["remedies"], f"{len(mine)} remedies")
    check("log level names identical",
          set(P.vocab("log_levels")) == set(legacy["log_levels"]))
    for pat in ("secret_name", "sensitive_log", "nonsecret_literal"):
        check(f"pattern `{pat}` identical", P.vocab(pat) == legacy["patterns"][pat])

    check("fp_rules identical to policy/python-web.yaml",
          P.fp_rules == legacy["fp_rules"], f"{P.fp_rules}")

    # EVERY VALUE COPIED INTO A PACK FROM CODE GETS A CONTROL. Four of these were duplicated
    # with nothing checking them, and one -- the browser `inert` pattern -- had ALREADY
    # diverged: written as a readable multi-line block scalar, it carried newlines the
    # compiled regex does not, so the pack documented a different regex than the lane ran.
    # A value duplicated into config with no equality control is not configuration; it is a
    # second source of truth waiting to drift, and drift is undetectable from any total.
    bjs = loader._read(os.path.join(loader.PACKS, "browser-js", "security", "commodity",
                                    "pack.yaml"))["patterns"]
    check("browser `sinks` pattern identical to the compiled lane",
          bjs["sinks"] == repo_security.SINKS)
    check("browser `markup` pattern identical to the compiled lane",
          bjs["markup"] == repo_security.MARKUP.pattern)
    check("browser `inert` pattern identical to the compiled lane",
          bjs["inert"] == repo_security.INERT.pattern,
          "character-for-character, newlines included")
    fw = loader._read(os.path.join(loader.PACKS, "python", "authorization", "fastapi",
                                   "pack.yaml"))["framework"]
    check("FastAPI route methods identical to repo_authz.METHODS",
          set(fw["route_decorator_methods"]) == repo_authz.METHODS)
    check("FastAPI write methods identical to repo_authz.WRITE",
          set(fw["write_methods"]) == repo_authz.WRITE)

    task = yaml.safe_load(open(LEGACY_TASK))
    prof = loader._read(os.path.join(loader.PROJECTS, "notes-api.yaml"))
    check("notes-api spec routes identical",
          set(prof["spec"]["routes"]) == set(task["spec_routes"]),
          f"{len(task['spec_routes'])} routes")
    check("notes-api services and probe identity identical",
          prof["spec"]["services"] == task["services"]
          and prof["spec"]["probe_identity"] == task["probe_identity"])


# ---------------------------------------------------------------------------
# (B) MERGE SEMANTICS — adversarial controls on the tier contract
# ---------------------------------------------------------------------------
SANDBOX = None


def _sandbox():
    """A miniature pack tree we can misuse without touching the real one."""
    global SANDBOX
    SANDBOX = tempfile.mkdtemp(prefix="packtest-")
    packs = os.path.join(SANDBOX, "packs")
    os.makedirs(os.path.join(packs, "general"))
    os.makedirs(os.path.join(packs, "toy", "security", "commodity"))
    os.makedirs(os.path.join(SANDBOX, "projects"))
    os.makedirs(os.path.join(SANDBOX, "orgs", "bad", "controls"))

    w = lambda p, s: open(p, "w").write(s)
    w(os.path.join(packs, "general", "pack.yaml"),
      "id: general\nversion: 1\ntier: commodity\nvocabulary: {generic_remedy: fix it}\n"
      "scan: {skip_dirs: [.git]}\n")
    w(os.path.join(packs, "general", "severity.yaml"),
      "weights: {HIGH: 3, MEDIUM: 2, LOW: 1}\n")
    w(os.path.join(packs, "toy", "pack.yaml"),
      "id: toy\nversion: 1\ntier: commodity\nruntime: toy\n"
      "detect: {extensions: ['.toy']}\nunmeasured_verdict: no_parse\n")
    w(os.path.join(packs, "toy", "security", "commodity", "pack.yaml"),
      "id: toy/security\nversion: 1\ntier: commodity\nruntime: toy\naxis: security\n"
      "requires_facts: [owner]\n"
      "rules:\n  toy/leak:\n    sev: HIGH\n    remedy: stop leaking\n    attack: reads it\n"
      "    overreach: none known\n")
    w(os.path.join(packs, "toy", "security", "commodity", "LIMITS.md"), "toy limits\n")
    loader.PACKS = packs
    loader.PROJECTS = os.path.join(SANDBOX, "projects")
    loader.ORGS = os.path.join(SANDBOX, "orgs")
    return SANDBOX


def _profile(name, body):
    open(os.path.join(loader.PROJECTS, f"{name}.yaml"), "w").write(
        f"id: projects/{name}\nversion: 1\ntier: project\n"
        f"runtimes: [toy]\naxes: [security]\n{body}")


def _org(name, body):
    d = os.path.join(loader.ORGS, name)
    os.makedirs(os.path.join(d, "controls"), exist_ok=True)
    open(os.path.join(d, "controls", "still-caught.toy"), "w").write("a real defect\n")
    open(os.path.join(d, "pack.yaml"), "w").write(
        f"id: orgs/{name}\nversion: 1\ntier: org\n{body}")


def merge_semantics():
    print("\n-- (B) merge semantics: what a layer may and may not do --")
    real = (loader.PACKS, loader.PROJECTS, loader.ORGS)
    try:
        _sandbox()

        _profile("base", "facts: {owner: platform}\n")
        P = load_policy("base")
        check("baseline profile resolves", "toy/leak" in P.rules)
        base_hash = P.manifest_hash

        # --- a missing fact is named, not defaulted
        _profile("nofact", "facts: {}\n")
        expect_refused("a pack's required fact, unsupplied, is REFUSED and named",
                       lambda: load_policy("nofact"), must_mention="owner")

        # --- redefinition across owners
        _org("redef", "rules:\n  toy/leak:\n    sev: LOW\n    remedy: ignore it\n"
                      "    attack: none\n")
        _profile("redef", "facts: {owner: platform}\norg: redef\n")
        expect_refused("an org layer REDEFINING a commodity rule is refused",
                       lambda: load_policy("redef"), must_mention="never redefine")

        # --- reweighting is legal and recorded
        _org("weight", "reweight: {toy/leak: LOW}\n")
        _profile("weight", "facts: {owner: platform}\norg: weight\n")
        P = load_policy("weight")
        check("an org layer MAY reweight a commodity rule",
              P.rules["toy/leak"]["sev"] == "LOW")
        check("the reweight is recorded in the rule's history",
              any("reweighted HIGH -> LOW" in h for h in P.rules["toy/leak"]["history"]),
              P.rules["toy/leak"]["history"][-1])

        # --- reweighting something that does not exist is a typo, not a policy
        _org("typo", "reweight: {toy/leek: LOW}\n")
        _profile("typo", "facts: {owner: platform}\norg: typo\n")
        expect_refused("reweighting an unknown rule is refused",
                       lambda: load_policy("typo"), must_mention="unknown rule")

        # --- suppression WITHOUT a justification
        _org("nojust", "suppress:\n  - rule: toy/leak\n"
                       "    negative_control: controls/still-caught.toy\n")
        _profile("nojust", "facts: {owner: platform}\norg: nojust\n")
        expect_refused("a suppression with NO justification is refused",
                       lambda: load_policy("nojust"), must_mention="justification")

        # --- suppression WITHOUT a paired negative control
        _org("noneg", "suppress:\n  - rule: toy/leak\n    justification: we handle it\n")
        _profile("noneg", "facts: {owner: platform}\norg: noneg\n")
        expect_refused("a suppression with NO paired negative control is refused",
                       lambda: load_policy("noneg"), must_mention="negative_control")

        # --- suppression naming a control that does not exist
        _org("ghost", "suppress:\n  - rule: toy/leak\n    justification: we handle it\n"
                      "    negative_control: controls/nope.toy\n")
        _profile("ghost", "facts: {owner: platform}\norg: ghost\n")
        expect_refused("a negative control that does not exist on disk is refused",
                       lambda: load_policy("ghost"), must_mention="does not exist")

        # --- THE ONE THAT MATTERS: a legal suppression does not make the rule vanish
        _org("legal", "suppress:\n  - rule: toy/leak\n"
                      "    justification: handled by the edge proxy, reviewed 2026-07\n"
                      "    negative_control: controls/still-caught.toy\n")
        _profile("legal", "facts: {owner: platform}\norg: legal\n")
        P = load_policy("legal")
        check("a justified suppression is ACCEPTED", len(P.suppressed) == 1)
        check("...and the rule is STILL PRESENT, not deleted", "toy/leak" in P.rules)
        check("...and it is recorded as suppressed, by whom, and why",
              P.suppressed[0]["by"].startswith("orgs/legal")
              and "edge proxy" in P.suppressed[0]["justification"])
        check("...so the gate can refuse a candidate that raises the count",
              P.is_suppressed("toy/leak") and len(P.suppressed) > 0,
              "s is a coordinate of the state, not a hidden edit")

        # --- facts layer by EXTENDING, so an org states the common case once
        _org("facts", "facts: {owner: [platform], reviewers: [sec-team]}\n")
        _profile("facts", "facts: {owner: [payments]}\norg: facts\n")
        P = load_policy("facts")
        check("an org fact and a project fact COMBINE rather than one replacing the other",
              P.fact("owner") == frozenset({"platform", "payments"}),
              sorted(P.fact("owner")))
        check("...and a fact only the org supplies survives",
              P.fact("reviewers") == frozenset({"sec-team"}))

        # --- binding an undeclared rule
        _org("badbind", "binds: [toy/nothing]\n")
        _profile("badbind", "facts: {owner: platform}\norg: badbind\n")
        expect_refused("binding a detector to an undeclared rule is refused",
                       lambda: load_policy("badbind"), must_mention="no loaded pack declares")

        # --- deployment context
        _profile("ctx", "facts: {owner: platform}\n"
                        "deployment: {network: internal}\n"
                        "context_reweight:\n  - rule: toy/leak\n"
                        "    when: {network: internal}\n    sev: LOW\n"
                        "    why: unreachable from outside the internal network\n")
        P = load_policy("ctx")
        check("deployment context reweights a rule when the context MATCHES",
              P.rules["toy/leak"]["sev"] == "LOW")
        check("...and the reason is in the history, not just in someone's head",
              any("context reweight" in h and "unreachable" in h
                  for h in P.rules["toy/leak"]["history"]))

        _profile("ctx2", "facts: {owner: platform}\n"
                         "deployment: {network: host}\n"
                         "context_reweight:\n  - rule: toy/leak\n"
                         "    when: {network: internal}\n    sev: LOW\n"
                         "    why: unreachable from outside the internal network\n")
        check("...and does NOT apply when the context does not match",
              load_policy("ctx2").rules["toy/leak"]["sev"] == "HIGH",
              "change the deployment and the finding comes back at full weight")

        _profile("ctx3", "facts: {owner: platform}\n"
                         "deployment: {network: internal}\n"
                         "context_reweight:\n  - rule: toy/leak\n"
                         "    when: {network: internal}\n    sev: LOW\n")
        expect_refused("a context reweight with no `why` is refused",
                       lambda: load_policy("ctx3"), must_mention="`why`")

        # --- held-out isolation
        os.makedirs(os.path.join(loader.PACKS, "toy", "security", "auditor"))
        open(os.path.join(loader.PACKS, "toy", "security", "auditor", "pack.yaml"),
             "w").write("id: toy/security/auditor\nversion: 1\ntier: commodity\n"
                        "runtime: toy\naxis: security\nheldout: true\n")
        expect_refused("a held-out pack cannot be loaded into the loop",
                       lambda: load_policy("base"), must_mention="held-out")
        shutil.rmtree(os.path.join(loader.PACKS, "toy", "security", "auditor"))

        # --- provenance
        check("the same profile resolves to the same manifest hash",
              load_policy("base").manifest_hash == base_hash, base_hash)
        check("adding an org layer CHANGES the manifest hash",
              load_policy("weight").manifest_hash != base_hash,
              "two runs are comparable iff their manifests match")
    finally:
        loader.PACKS, loader.PROJECTS, loader.ORGS = real
        if SANDBOX:
            shutil.rmtree(SANDBOX, ignore_errors=True)


# ---------------------------------------------------------------------------
# (C) ROUTING — the polyglot claim
# ---------------------------------------------------------------------------
def routing():
    print("\n-- (C) routing: every module to its own language's packs --")
    subject_present = os.path.isdir(SUBJECT)
    root = SUBJECT if subject_present else loader.PACKS
    P = load_policy("dealership", root=root)
    inv = P.inventory
    check("the repository is inventoried per runtime", len(inv.by_runtime) >= 2,
          ", ".join(f"{k}={len(v)}" for k, v in sorted(inv.by_runtime.items())))
    check("python modules route to the python packs",
          all(p.runtime in (None, "python") or p.tier in ("org", "project")
              for p in P.for_runtime("python").packs))
    check("browser files route to the browser packs",
          "browser-js/security" in {p.id for p in P.for_runtime("browser-js").packs})
    check("the project layer is present in BOTH views (coherence)",
          "projects/dealership" in {p.id for p in P.for_runtime("python").packs}
          and "projects/dealership" in {p.id for p in P.for_runtime("browser-js").packs},
          "one set of facts, many detectors")
    # A cross-language rule must reach ONLY the languages that can detect it. Before this
    # control the Python view carried four browser-only practice rules, so an agent editing
    # a FastAPI router would have been advised about localStorage. Advice for the wrong
    # language is worse than none: it is how a practitioner learns to stop reading the tool.
    py = set(P.for_runtime("python").rules)
    js = set(P.for_runtime("browser-js").rules)
    check("a browser-only rule does NOT leak into the python view",
          not {"practice/half-wired-state", "practice/write-without-read",
               "practice/unchecked-response",
               "practice/inconsistent-render-path"} & py,
          f"python practice rules: {sorted(r for r in py if r.startswith('practice/'))}")
    check("a python-only rule does NOT leak into the browser view",
          "practice/divergent-resource-access" not in js)
    check("...and each view DOES carry the rules its own packs bind",
          "practice/divergent-resource-access" in py
          and "practice/half-wired-state" in js,
          "one declaration in general/, bound per language")
    check("both views share the project's facts and the severity scale",
          P.for_runtime("python").fact("public_routes")
          == P.for_runtime("browser-js").fact("public_routes")
          and P.for_runtime("python").severity == P.for_runtime("browser-js").severity)

    if subject_present:
        check("a runtime with NO lanes is reported UNREAD, not clean",
              "container" in inv.unread, f"unread: {sorted(inv.unread)}")
        check("a file no runtime claims is reported as a blind spot",
              any(f.endswith(".sql") for f in inv.unclaimed) or "sql" in inv.by_runtime,
              f"unclaimed: {inv.unclaimed}")
    else:
        skip("blind-spot reporting on the brownfield subject",
             "the subject repository is not part of the standalone distribution")


def main():
    equivalence()
    merge_semantics()
    routing()
    if _skipped:
        print(f"\n{len(_skipped)} control(s) SKIPPED (not run, therefore not passed): "
              + "; ".join(_skipped))
    print("\nall pack-system controls that ran passed" if _ok else "\nCONTROLS FAILED")
    return 0 if _ok else 1


if __name__ == "__main__":
    sys.exit(main())
