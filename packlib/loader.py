#!/usr/bin/env python3
"""Compose a rule set out of packs.

WHAT A PACK IS
A pack is one cell of a three-dimensional grid, and the directory layout says so:

    packs/<runtime>/<axis>/<tier>/pack.yaml

  runtime   python, browser-js, sql, dockerfile ...   which parser can open the file
  axis      security, authorization, practice ...     what the gate promises
  tier      commodity < framework < org < project     who owns it, and what they may do

`packs/general/` is the fourth thing: the vocabulary and doctrine that belong to no single
language -- the one severity scale, the word lists ("secret", "is_admin", "token") that mean
the same thing in every runtime, and cross-language practice rules that each language pack
BINDS to a detector. Keeping those in one place is what makes a HIGH from the browser lane
and a HIGH from bandit the same number to the gate.

WHY IT IS LAYERED RATHER THAN FORKED
An organisation's coding standards are not a different security policy; they are an overlay
on one. So a lower tier may add a rule, reweight a rule, supply facts a higher pack declared
it needs (`auth_deps`, `public_routes`), or suppress a rule -- but it may never delete or
redefine what a higher tier owns, and a suppression is only accepted with a written
justification and a paired negative control.

THE ONE INVARIANT WORTH STATING TWICE
A suppressed rule does not disappear; it moves to a recorded coordinate. `resolved.suppressed`
is carried into the run state alongside (w, r, v, m) and the gate refuses any candidate that
raises it. Without that, an overlay is a legal way to shrink the search space, and every
total still looks like progress -- the exact failure this project documents everywhere else.

USAGE
    from packlib import load_policy
    P = load_policy("dealership")        # projects/dealership.yaml
    P.weight("HIGH")                     # 3
    P.vocab("secretish")                 # frozenset of substrings
    P.fact("auth_deps")                  # frozenset, supplied by the project
    P.remedy("B105")                     # remediation text
    P.manifest_hash                      # goes in the result file
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                      # evidence/
PACKS = os.path.join(ROOT, "packs")
PROJECTS = os.path.join(ROOT, "projects")
ORGS = os.path.join(ROOT, "orgs")

# Ascending authority. Position in this list is the whole merge order.
TIERS = ("commodity", "framework", "org", "project")


class PackError(Exception):
    """A pack is malformed, or a layer tried to do something a layer may not do."""


def _read(path):
    with open(path, encoding="utf8") as f:
        text = f.read()
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def _need(d, key, where):
    if key not in d:
        raise PackError(f"{where}: missing required key '{key}'")
    return d[key]


class Pack:
    """One loaded pack.yaml, with its directory kept so controls/LIMITS resolve."""

    def __init__(self, d, path):
        self.path = path
        self.dir = os.path.dirname(path)
        w = os.path.relpath(path, ROOT)
        self.id = _need(d, "id", w)
        self.version = str(_need(d, "version", w))
        self.tier = _need(d, "tier", w)
        if self.tier not in TIERS:
            raise PackError(f"{w}: tier '{self.tier}' is not one of {TIERS}")
        self.runtime = d.get("runtime")
        self.axis = d.get("axis")
        self.description = d.get("description", "")
        # what the pack contributes
        self.rules = d.get("rules", {}) or {}
        self.binds = list(d.get("binds", []) or [])
        self.vocabulary = d.get("vocabulary", {}) or {}
        self.facts = d.get("facts", {}) or {}
        self.requires_facts = list(d.get("requires_facts", []) or [])
        self.lanes = d.get("lanes", {}) or {}
        self.scan = d.get("scan", {}) or {}
        self.fp_rules = d.get("fp_rules", {}) or {}
        self.detect = d.get("detect", {}) or {}
        self.status = d.get("status", "active")
        self.patterns = d.get("patterns", {}) or {}
        self.framework = d.get("framework", {}) or {}
        self.controls = d.get("controls", {}) or {}
        self.deployment = d.get("deployment", {}) or {}
        self.context_reweight = list(d.get("context_reweight", []) or [])
        self.spec = d.get("spec", {}) or {}
        # obligations (checked by packtest, recorded here)
        self.limits = d.get("limits", "LIMITS.md")
        self.heldout = bool(d.get("heldout", False))
        self.unmeasured_verdict = d.get("unmeasured_verdict")
        # overlay operations (org/project tiers)
        self.reweight = d.get("reweight", {}) or {}
        self.suppress = d.get("suppress", []) or []

    def limits_path(self):
        return os.path.join(self.dir, self.limits)

    def __repr__(self):
        return f"<Pack {self.id}@{self.tier} v{self.version}>"


class ResolvedPolicy:
    """The merged rule set a run actually executed against."""

    def __init__(self, profile_name, packs, rules, vocabulary, facts, severity,
                 scan, suppressed, lanes, deployment=None, spec=None, inventory=None,
                 runtimes=(), fp_rules=None):
        self.profile = profile_name
        self.packs = packs                  # in resolution order
        self.rules = rules                  # rule_id -> dict(sev, remedy, owner, ...)
        self._vocab = vocabulary
        self._facts = facts
        self.severity = severity
        self.scan = scan
        self.fp_rules = fp_rules or {}
        self.suppressed = suppressed        # list of dicts: rule, by, justification
        self.lanes = lanes
        self.deployment = deployment or {}  # where this code runs
        self.spec = spec or {}
        self.inventory = inventory          # what is in the tree, and who can read it
        self.runtimes = list(runtimes)

    # ---- polyglot views -------------------------------------------------
    def for_runtime(self, runtime):
        """The packs that read this runtime — general + that runtime + the overlays.

        This is what the MCP server asks per module: a `.py` file is judged by the Python
        packs, a `.html` file by the browser packs, and both by the general vocabulary, the
        org standards and the project facts. Coherence comes from the shared layers; only
        the detectors differ.

        A cross-language rule is DECLARED in `general/` and BOUND by whichever language packs
        can detect it. Ownership alone is therefore not enough to decide whether it belongs
        in this view: `practice/half-wired-state` is owned by `general/practice` and detected
        only in a browser, and handing it to a Python module means telling someone editing a
        FastAPI router about `localStorage`. Advice for the wrong language is worse than no
        advice — it is the fastest way to teach a practitioner to stop reading the output.
        So a bound rule appears only where something in this view actually binds it.
        """
        keep = [p for p in self.packs
                if p.runtime in (None, runtime) or p.tier in ("org", "project")]
        kept_ids = {p.id for p in keep}
        rules = {}
        for rid, r in self.rules.items():
            if r["owner"] not in kept_ids:
                continue
            bound = r.get("bound_by")
            if bound and not (set(bound) & kept_ids):
                continue
            rules[rid] = r
        return ResolvedPolicy(self.profile, keep, rules, self._vocab, self._facts,
                              self.severity, self.scan, self.suppressed,
                              {k: v for k, v in self.lanes.items()},
                              self.deployment, self.spec, self.inventory, [runtime],
                              self.fp_rules)

    def lanes_by_runtime(self):
        out = {}
        for p in self.packs:
            if p.lanes and p.runtime:
                out.setdefault(p.runtime, []).extend(p.lanes)
        return out

    # ---- accessors ------------------------------------------------------
    def weight(self, sev):
        return self.severity.get(str(sev).upper(), 1)

    def vocab(self, name):
        if name not in self._vocab:
            raise PackError(f"no vocabulary '{name}' in profile '{self.profile}'; "
                            f"have: {sorted(self._vocab)}")
        v = self._vocab[name]
        return frozenset(v) if isinstance(v, (list, set, tuple)) else v

    def fact(self, name):
        if name not in self._facts:
            raise PackError(
                f"fact '{name}' is required by a pack but no layer supplies it. "
                f"Add it to projects/{self.profile}.yaml under `facts:`.")
        v = self._facts[name]
        return frozenset(v) if isinstance(v, (list, set, tuple)) else v

    def has_fact(self, name):
        return name in self._facts

    def remedy(self, rule_id, default=None):
        r = self.rules.get(rule_id)
        if r and r.get("remedy"):
            return r["remedy"]
        return default if default is not None else self._vocab.get(
            "generic_remedy", "Address the flagged issue without weakening any control.")

    def severity_of(self, rule_id, default="MEDIUM"):
        r = self.rules.get(rule_id)
        return (r or {}).get("sev", default)

    def is_suppressed(self, rule_id):
        return any(s["rule"] == rule_id for s in self.suppressed)

    # ---- provenance -----------------------------------------------------
    @property
    def manifest(self):
        """Exactly what produced this verdict. Two runs compare iff these match."""
        return {
            "profile": self.profile,
            "packs": [{"id": p.id, "version": p.version, "tier": p.tier,
                       "runtime": p.runtime, "axis": p.axis} for p in self.packs],
            "rules": len(self.rules),
            "suppressed": self.suppressed,
        }

    @property
    def manifest_hash(self):
        blob = json.dumps(self.manifest, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def explain(self, rule_id):
        """Where did this rule come from, and who touched it? For humans."""
        r = self.rules.get(rule_id)
        if not r:
            return f"{rule_id}: not in this profile"
        out = [f"{rule_id}  sev={r['sev']}  owner={r['owner']}"]
        for ev in r.get("history", []):
            out.append(f"    {ev}")
        return "\n".join(out)

    def __repr__(self):
        return (f"<ResolvedPolicy {self.profile}: {len(self.packs)} packs, "
                f"{len(self.rules)} rules, {len(self.suppressed)} suppressed, "
                f"manifest {self.manifest_hash}>")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def _load_pack_dir(d):
    p = os.path.join(d, "pack.yaml")
    return Pack(_read(p), p) if os.path.isfile(p) else None


def _discover(runtime, axis, frameworks):
    """Packs for one runtime+axis: every commodity pack, plus named frameworks."""
    base = os.path.join(PACKS, runtime, axis)
    if not os.path.isdir(base):
        return []
    found = []
    for name in sorted(os.listdir(base)):
        pack = _load_pack_dir(os.path.join(base, name))
        if pack is None:
            continue
        if pack.tier == "commodity" or name in frameworks or pack.id in frameworks:
            found.append(pack)
    # commodity first, then frameworks: ascending authority within the runtime
    return sorted(found, key=lambda p: TIERS.index(p.tier))


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------
def _apply(pack, rules, vocabulary, facts, scan, fp_rules, suppressed):
    """Fold one pack into the accumulating policy, enforcing the tier contract."""
    where = f"{pack.id}@{pack.tier}"

    # --- vocabulary and facts: later layers extend, and may override their own kind
    for k, v in pack.vocabulary.items():
        if isinstance(v, list) and isinstance(vocabulary.get(k), list):
            vocabulary[k] = sorted(set(vocabulary[k]) | set(v))
        else:
            vocabulary[k] = v
    for k, v in pack.facts.items():
        # List facts EXTEND rather than replace, so an org can state what every project
        # here has in common and a project can add its own without repeating them. The one
        # case worth naming: extending `public_routes` is the only fact edit that WEAKENS a
        # lane (more routes declared anonymous = fewer findings), which is precisely why
        # every entry in it is meant to be a decision someone signed rather than an omission.
        if isinstance(v, list) and isinstance(facts.get(k), list):
            facts[k] = sorted(set(facts[k]) | set(v))
        else:
            facts[k] = v
    for k, v in pack.scan.items():
        if isinstance(v, list) and isinstance(scan.get(k), list):
            scan[k] = sorted(set(scan[k]) | set(v))
        else:
            scan[k] = v
    # False-positive policy: which rules a pattern lane is too imprecise to gate on (they
    # defer to dataflow), and the keyword set the validators use. This was declared in the
    # pack and read by nobody for one revision -- data that LOOKS like configuration and
    # configures nothing is worse than no data, because a reader will believe it.
    for k, v in pack.fp_rules.items():
        if isinstance(v, list) and isinstance(fp_rules.get(k), list):
            fp_rules[k] = sorted(set(fp_rules[k]) | set(v))
        else:
            fp_rules[k] = v

    # --- rules: ADD is always legal; REDEFINE across owners is never legal
    for rid, spec in pack.rules.items():
        spec = dict(spec or {})
        spec.setdefault("sev", "MEDIUM")
        if rid in rules and rules[rid]["owner"] != pack.id:
            raise PackError(
                f"{where} redefines rule '{rid}' owned by {rules[rid]['owner']}. "
                f"A lower tier may reweight or suppress a rule, never redefine it. "
                f"If you meant a different rule, give it a new id.")
        spec["owner"] = pack.id
        spec["history"] = rules.get(rid, {}).get("history", []) + [f"defined by {where}"]
        rules[rid] = spec

    # --- binds: attach a detector to a rule ANOTHER pack declared, without redefining it.
    #     This is how one invariant keeps one id and one weight across many languages.
    for rid in pack.binds:
        if rid not in rules:
            raise PackError(
                f"{where} binds '{rid}', which no loaded pack declares. A binding is a "
                f"detector for an existing rule; if you meant to introduce a rule, declare "
                f"it (with its remedy and its stated attack or failure).")
        rules[rid]["history"] = rules[rid]["history"] + [f"detected by {where}"]
        rules[rid].setdefault("bound_by", []).append(pack.id)

    # --- reweight: legal, but only onto the shared scale, and only for rules that exist
    for rid, sev in pack.reweight.items():
        if rid not in rules:
            raise PackError(f"{where} reweights unknown rule '{rid}'. Reweighting a rule "
                            f"that no loaded pack defines is a typo, not a policy.")
        old = rules[rid]["sev"]
        rules[rid] = dict(rules[rid], sev=sev)
        rules[rid]["history"] = rules[rid]["history"] + [
            f"reweighted {old} -> {sev} by {where}"]

    # --- suppress: legal ONLY with a justification and a paired negative control,
    #     and the rule is RECORDED as suppressed rather than removed.
    for s in pack.suppress:
        rid = _need(s, "rule", f"{where} suppress entry")
        if rid not in rules:
            raise PackError(f"{where} suppresses unknown rule '{rid}'.")
        if not s.get("justification"):
            raise PackError(
                f"{where} suppresses '{rid}' with no justification. Every suppression is a "
                f"decision someone signs: say why, in the pack, where a reviewer sees it.")
        neg = s.get("negative_control")
        if not neg:
            raise PackError(
                f"{where} suppresses '{rid}' with no negative_control. Name an artifact "
                f"carrying a real defect this suppression must still catch, or the "
                f"suppression is free to widen without anyone noticing.")
        if not os.path.isfile(os.path.join(pack.dir, neg)):
            raise PackError(f"{where}: negative_control '{neg}' does not exist "
                            f"(looked in {os.path.relpath(pack.dir, ROOT)}).")
        rules[rid]["history"] = rules[rid]["history"] + [f"suppressed by {where}"]
        suppressed.append({"rule": rid, "by": where,
                           "justification": s["justification"],
                           "negative_control": neg})


def _all_runtime_packs():
    """Every runtime pack that exists, whether or not this profile loads its lanes."""
    out = {}
    if not os.path.isdir(PACKS):
        return out
    for name in sorted(os.listdir(PACKS)):
        if name == "general":
            continue
        p = _load_pack_dir(os.path.join(PACKS, name))
        if p and p.runtime:
            out[p.runtime] = p
    return out


def _apply_context(rules, deployment, entries, where):
    """Reweight rules against WHERE THE CODE RUNS, with the reason recorded.

    Carlos's observation, and it is a real one: a container changes what a finding means.
    Binding 0.0.0.0 is the correct way to reach a service on an internal network behind a
    proxy and a genuine defect on a host. Rather than hard-code that special case into the
    Python pack (where it currently lives, as prose in a remedy string), a project declares
    its deployment and any layer may price findings against it.

    The reweight is NOT a suppression: the rule keeps its place, its weight moves, and the
    history says who moved it and why. Change `network:` back to `host` and the finding
    returns at full weight without anyone having to remember it existed.
    """
    for e in entries:
        rid = _need(e, "rule", f"{where} context_reweight entry")
        if rid not in rules:
            continue                    # a rule this profile does not load; not an error
        cond = e.get("when", {}) or {}
        if not all(deployment.get(k) == v for k, v in cond.items()):
            continue
        if not e.get("why"):
            raise PackError(
                f"{where} reweights '{rid}' against deployment context with no `why`. An "
                f"unexplained reweight is indistinguishable from an unjustified suppression "
                f"six months from now.")
        old = rules[rid]["sev"]
        rules[rid] = dict(rules[rid], sev=e["sev"])
        rules[rid]["history"] = rules[rid]["history"] + [
            f"context reweight {old} -> {e['sev']} by {where} "
            f"(when {cond}): {e['why'].strip().splitlines()[0]}"]


def load_policy(profile="dealership", root=None, extra_packs=()):
    """Resolve a project profile into the rule set the harness will run.

    `root` is the repository being judged. It is optional, but with `runtimes: auto` in the
    profile it is what lets the loader inventory the tree and load packs for the languages
    that are ACTUALLY there — and report the ones nothing can read.
    """
    ppath = os.path.join(PROJECTS, f"{profile}.yaml")
    if not os.path.isfile(ppath):
        have = sorted(f[:-5] for f in os.listdir(PROJECTS) if f.endswith(".yaml")) \
            if os.path.isdir(PROJECTS) else []
        raise PackError(f"no project profile '{profile}' (projects/{profile}.yaml). "
                        f"have: {have}")
    prof = _read(ppath)
    axes = list(prof.get("axes", []))
    frameworks = set(prof.get("frameworks", []))
    declared = prof.get("runtimes", [])

    # ---- which runtimes? Either the profile says, or we look. -------------
    runtime_packs = _all_runtime_packs()
    detectors = {rt: p.detect for rt, p in runtime_packs.items() if p.detect}
    inv = None
    if declared == "auto" or declared == ["auto"]:
        if root is None:
            raise PackError(
                f"projects/{profile}.yaml says `runtimes: auto`, which inventories the "
                f"repository — so load_policy needs `root=<path to the repo>`.")
        skip = set(_read(os.path.join(PACKS, "general", "pack.yaml"))
                   .get("scan", {}).get("skip_dirs", []))
        globs = []
        for p in runtime_packs.values():
            skip |= set(p.scan.get("skip_dirs", []))
            globs += list(p.scan.get("skip_globs", []))
        from . import detect as _detect
        # A `.js` file is claimed by both browser-js and node-js. The profile breaks the
        # tie; absent a preference the browser wins, because that is the environment whose
        # blind spot this project actually measured.
        pref = list(prof.get("prefer_runtimes", ["browser-js"]))
        inv = _detect.inventory(root, detectors, skip, globs, preferred=pref)
        runtimes = sorted(inv.by_runtime)
    else:
        runtimes = list(declared)

    chain = []
    # 1. general: the scale, the shared vocabulary, cross-language rule declarations
    gen = _load_pack_dir(os.path.join(PACKS, "general"))
    if gen is None:
        raise PackError("packs/general/pack.yaml is missing; it defines the severity "
                        "scale every other pack selects from.")
    chain.append(gen)
    for sub in sorted(prof.get("general_axes", ["practice"])):
        sp = _load_pack_dir(os.path.join(PACKS, "general", sub))
        if sp:
            chain.append(sp)

    # 2. runtime defaults, then each axis under that runtime
    for rt in runtimes:
        rp = _load_pack_dir(os.path.join(PACKS, rt))
        if rp:
            chain.append(rp)
        for ax in axes:
            chain.extend(_discover(rt, ax, frameworks))

    # 3. org overlay, 4. project overlay
    org = prof.get("org")
    if org:
        cands = [os.path.join(ORGS, org, "pack.yaml"), os.path.join(ORGS, f"{org}.yaml")]
        op = next((c for c in cands if os.path.isfile(c)), None)
        if op is None:
            raise PackError(f"profile names org '{org}' but neither "
                            f"orgs/{org}/pack.yaml nor orgs/{org}.yaml exists.")
        chain.append(Pack(_read(op), op))
    for d in extra_packs:
        p = _load_pack_dir(d)
        if p:
            chain.append(p)
    chain.append(Pack(dict(prof, tier="project"), ppath))

    severity = _read(os.path.join(PACKS, "general", "severity.yaml"))["weights"]
    rules, vocabulary, facts, scan, fp_rules, suppressed = {}, {}, {}, {}, {}, []
    for pack in chain:
        if pack.heldout:
            raise PackError(
                f"{pack.id} is declared held-out and must never be loaded into a repair "
                f"loop. Its agreement is only evidence while it stays outside.")
        _apply(pack, rules, vocabulary, facts, scan, fp_rules, suppressed)

    # every fact a loaded pack said it needs must be supplied by some layer
    missing = sorted({f for p in chain for f in p.requires_facts} - set(facts))
    if missing:
        raise PackError(
            f"profile '{profile}' loads packs requiring facts nobody supplies: {missing}. "
            f"These are the things only you know about your project -- add them under "
            f"`facts:` in projects/{profile}.yaml.")

    # Deployment context: the project's own, then any layer's reweights against it.
    deployment = dict(prof.get("deployment", {}) or {})
    for p in chain:
        if p.context_reweight:
            _apply_context(rules, deployment, p.context_reweight, f"{p.id}@{p.tier}")

    lanes = {}
    for p in chain:
        lanes.update(p.lanes)

    if inv is not None:
        # Which runtimes did this profile actually load lanes for? Everything else in the
        # tree is a declared blind spot, and the inventory says so out loud.
        with_lanes = {p.runtime for p in chain if p.lanes and p.runtime}
        inv.lanes_for = {rt: rt in with_lanes for rt in inv.by_runtime}

    return ResolvedPolicy(profile, chain, rules, vocabulary, facts, severity, scan,
                          suppressed, lanes, deployment, prof.get("spec", {}), inv,
                          runtimes, fp_rules)


if __name__ == "__main__":
    import sys
    P = load_policy(sys.argv[1] if len(sys.argv) > 1 else "dealership")
    print(P)
    print("\npacks, in resolution order:")
    for p in P.packs:
        print(f"  {p.tier:<10} {p.id:<38} v{p.version}  {p.description[:40]}")
    print(f"\nrules: {len(P.rules)}   facts: {sorted(P._facts)}")
    print(f"vocabulary: {sorted(P._vocab)}")
    if P.suppressed:
        print("\nsuppressed (recorded, not removed):")
        for s in P.suppressed:
            print(f"  {s['rule']} by {s['by']}: {s['justification']}")
