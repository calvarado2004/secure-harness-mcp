#!/usr/bin/env python3
"""Blind mode: find the handler its own project treats differently, with no profile at all.

WHY A SECOND MODE EXISTS
The rest of this harness answers "is this endpoint authorized?" and that question has no
general answer: it depends on who may see what, which lives in the project and not in its
syntax. So every other lane requires the project to declare its trust boundaries first, and a
project that declares nothing correctly gets no verdict. That is right for repair, where a
wrong finding costs a repair round and can break a working product, and useless for the first
thing a practitioner actually does, which is point the tool at a repository nobody has
described and ask what is worth looking at.

THE PRIMITIVE THAT NEEDS NO POLICY
A project that applies a guard to twelve handlers and omits it on the thirteenth has stated
its policy already, in code. Consistency is decidable from the repository alone:

    peers   handlers whose disclosed vocabulary matches the guarded ones
    guard   a decorator carried by enough peers to be a convention rather than a coincidence
    finding a peer that lacks it, and that no stronger guard covers

Nothing above is a fact anyone has to supply, which is what makes it usable on unseen code.
The signature that defines a peer group is DERIVED, not named: it is the vocabulary the
guarded handlers share and the rest of the codebase does not, so it adapts to whatever this
project happens to call its data.

WHY IT NEVER GATES
A finding here is an anomaly relative to the project's own practice, not a demonstrated
defect. Gating repair on an inferred policy is how a harness breaks a working product, so
blind findings are ADVISORY by construction: they rank, a human confirms, and only a confirmed
policy is written into a profile and gated. Blind mode proposes; it does not adjudicate.

CALIBRATION IS PART OF THE RULE, NOT A FOOTNOTE
A consistency rule is only worth shipping if it stays quiet on healthy code, so the thresholds
below were chosen against a corpus of third-party projects rather than against the subject
that motivated the rule. `--calibrate` reproduces that measurement.
"""
import ast
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import flask_restx_authz as FR                       # noqa: E402  handler extraction

# A decorator carried by fewer handlers than this is a coincidence, not a convention.
MIN_CARRIERS = 3
# Of the handlers that look like peers, this fraction must already carry the guard before its
# absence anywhere means anything. Below it the project is not consistent enough to judge.
MIN_RATIO = 0.80
# A peer group smaller than this cannot support an anomaly: one of two is not an outlier.
MIN_PEERS = 4
# Guards that subsume a weaker one. Administrators already see everything.
DOMINATING = {"admins_only", "admin_only", "require_admin", "admins_required",
              "superuser_required", "root_only"}
# Verbs that DISCLOSE. A write that touches the same table is not a disclosure, and asking a
# visibility guard of it spends attention on an endpoint that returns nothing.
READ_VERBS = {"GET"}
# Vocabulary too common to distinguish one peer group from another.
# How authorization decorators are named across frameworks. This is a convention about
# GUARDS, not a fact about any project's data, which is what keeps blind mode project-agnostic.
GUARD_NAME = (re.compile(r"^check_(?P<noun>[a-z0-9]+)_visibility$"),
              re.compile(r"^require_(?P<noun>[a-z0-9]+)_access$"),
              re.compile(r"^(?P<noun>[a-z0-9]+)_visibility_required$"),
              re.compile(r"^ensure_(?P<noun>[a-z0-9]+)_permission$"))
# Attributes whose disclosure identifies a person. Generic across products.
IDENTITY_ATTRS = ("name", "username", "email", "handle")


def _noun(dec):
    for pat in GUARD_NAME:
        m = pat.match(dec)
        if m:
            return m.group("noun")
    return None


STOPWORDS = {"self", "id", "data", "get", "query", "filter", "all", "first", "json", "args",
             "request", "response", "success", "value", "type", "int", "str", "none", "true",
             "false", "list", "dict", "kwargs", "result", "count", "db", "session", "commit"}


# What refusing looks like, in any framework: a status, an exception, or a bounce to a login.
DENIAL = ("abort", "403", "401", "forbidden", "unauthorized", "permissiondenied",
          "accessdenied", "notauthorized", "login", "redirect")


def _guards(root, helpers):
    """Which decorators in this project can REFUSE a request.

    Blind mode has to separate a security convention from any other convention, and it cannot
    do that by name: `@doc` is applied consistently to thirteen of fifteen peers in one of our
    subjects and documents them. Restricting to decorators whose names look like guards would
    work on the projects we have already read and fail on the next one, which is the failure
    this mode exists to avoid.

    So the test is behavioural and framework-independent: resolve the decorator to its own
    definition and ask whether that definition can deny. A guard aborts, raises, answers 401
    or 403, or sends the caller to a login. A documentation decorator does none of those, and
    neither does a serialiser. This is the one thing blind mode needs to know about security,
    and it reads it out of the project rather than being told.
    """
    out = set()
    for name, defs in helpers.items():
        for d in defs:
            body = ast.dump(d).lower()
            # a decorator is a function that wraps and returns another callable
            wraps = "functools" in body or "wraps" in body or "def " in body
            if any(k in body for k in DENIAL) and wraps:
                out.add(name)
                break
    return out


FLASK_METHODS = {"get", "post", "put", "delete", "patch", "route"}


def _handlers(root):
    """Every route handler in the tree, in BOTH Flask spellings, with its disclosed vocabulary.

    Reading only class-mounted `Resource` methods made this mode untestable: of eight
    third-party Flask projects used to calibrate it, none use flask-restx, so the lane
    reported zero handlers and a zero finding count that meant nothing at all. A blind mode
    that only runs on one route form cannot be calibrated on the code a practitioner has, so
    it reads decorated view functions as well.
    """
    mounts = FR.restx_mounts(root)
    helpers = FR._helper_index(root)
    out = []
    for path in FR._py_files(root):
        tree = FR._parse(path)
        if tree is None:
            continue
        rel = os.path.relpath(path, root)

        def add(verb, route, func, cls):
            out.append({"verb": verb, "path": route or "/", "file": rel, "cls": cls,
                        "line": func.lineno, "decs": FR._decorator_names(func),
                        "node": func,
                        "reach": {t for t in FR._reach(func, helpers)
                                  if t not in STOPWORDS and len(t) > 3}})

        for verb, route, func, cls in FR.restx_handlers(tree, mounts):
            add(verb, route, func, cls)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                fn = dec.func
                if not isinstance(fn, ast.Attribute) or fn.attr not in FLASK_METHODS:
                    continue
                p_ = (dec.args[0].value
                      if dec.args and isinstance(dec.args[0], ast.Constant) else "")
                verbs = {"GET"}
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        verbs = {e.value.upper() for e in kw.value.elts
                                 if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if fn.attr != "route":
                    verbs = {fn.attr.upper()}
                for v in verbs:
                    add(v, p_, node, node.name)
                break
    return out


def _signature(carriers, others):
    """What the guarded handlers touch that the UNGUARDED ones do not.

    An earlier version kept tokens that were frequent among carriers and not universal in the
    corpus. That is not enough: `abort`, `is_admin` and `get_config` are frequent among the
    guarded handlers and frequent everywhere else too, so the peer group swelled to include
    every handler that mentions an administrator and the convention stopped looking like one.

    The signature is therefore DISCRIMINATIVE. A token earns its place by the margin between
    how often it appears in guarded handlers and how often it appears in the rest, which is
    what makes the group about the data these endpoints disclose rather than the framework
    they share.
    """
    if not carriers or not others:
        return set()
    ca, oa = Counter(), Counter()
    for h in carriers:
        ca.update(h["reach"])
    for h in others:
        oa.update(h["reach"])
    sig = set()
    for tok, k in ca.items():
        p_in = k / len(carriers)
        p_out = oa.get(tok, 0) / len(others)
        if p_in >= 0.6 and (p_in - p_out) >= 0.45:
            sig.add(tok)
    return sig


def _models(node, helpers):
    """The persistent models this handler reaches, following one call hop.

    WHY MODELS AND NOT IDENTIFIERS
    Grouping peers by the identifiers a handler mentions does not work: the vocabulary the
    guarded handlers share turns out to be `abort`, `authed`, `banned` and `freeze`, which is
    how they REFUSE rather than what they RETURN, so the peer group fills up with every
    endpoint that mentions an administrator. A model name is a fact about data. Two handlers
    that both read `Users` are peers whatever they are called and whatever framework mounts
    them, which is what lets this run on a project nobody has described.

    Detection is the SQLAlchemy idiom, `Model.query` and `session.query(Model)`, because that
    is what Flask applications overwhelmingly use. A project on a different ORM yields no
    models here and is reported as ungroupable rather than as clean.
    """
    out = set()

    def scan(n):
        for x in ast.walk(n):
            if isinstance(x, ast.Attribute) and x.attr == "query" and isinstance(x.value, ast.Name):
                out.add(x.value.id)
            elif isinstance(x, ast.Call) and getattr(x.func, "attr", None) == "query":
                for a in x.args:
                    if isinstance(a, ast.Name):
                        out.add(a.id)

    scan(node)
    for name in {getattr(c.func, "id", None) or getattr(c.func, "attr", None)
                 for c in ast.walk(node) if isinstance(c, ast.Call)}:
        for d in helpers.get(name, [])[:2]:
            scan(d)
    return out


def discover_by_model(root):
    """Blind mode with NO naming convention: peers are handlers that read the same model.

    KEPT AS A NEGATIVE RESULT, NOT AS A WORKING MODE.
    The intent was to drop the last project-independent assumption, the convention that a
    guard names what it protects. Grouping peers by the model they read is a data fact rather
    than a control-flow one, which fixed the previous failure, and it still does not work.
    Measured on the subject: the best any guard achieves over the readers of a model is

        Awards  28 readers, check_account_visibility on 9    ratio 0.32
        Users   29 readers, authed_only on 10                ratio 0.34
        Solves  11 readers, check_score_visibility on 5      ratio 0.45
        Teams   16 readers, check_account_visibility on 8    ratio 0.50

    Nowhere near a convention, and correctly so. Reading `Users` to return the CALLER'S OWN
    record is not the same act as reading `Users` to list other people, and a visibility guard
    belongs only on the second. Model identity cannot separate them, so the peer group mixes
    two populations and no ratio over it means anything. Lowering the threshold to admit 0.5
    would report every self-service endpoint in the project.

    THE MISSING PRIMITIVE, STATED SO IT CAN BE BUILT
    What distinguishes the two is where the query's scope comes from: an identifier derived
    from the authenticated caller, or one taken from client input. That is the same question
    `authz/decision-without-denial` already asks about ownership, and a general answer to it
    would subsume this rule and IDOR detection together. It is dataflow work, not a threshold.
    Until it exists, `discover` above carries the naming convention, and this function is
    retained so the negative result is reproducible rather than remembered.
    """
    hs = _handlers(root)
    helpers = FR._helper_index(root)
    can_refuse = _guards(root, helpers)
    if len(hs) < MIN_PEERS:
        return [], {"handlers": len(hs), "reason": "too few handlers"}

    for h in hs:
        h["models"] = _models(h["node"], helpers) if h.get("node") is not None else set()

    by_model = {}
    for h in hs:
        for m in h["models"]:
            by_model.setdefault(m, []).append(h)

    findings, groups = [], 0
    for model, peers in sorted(by_model.items()):
        readers = [h for h in peers
                   if h["verb"] in READ_VERBS and not (h["decs"] & DOMINATING)]
        if len(readers) < MIN_PEERS:
            continue
        for guard in sorted({d for h in readers for d in h["decs"]} & can_refuse):
            carried = [h for h in readers if guard in h["decs"]]
            if len(carried) < MIN_CARRIERS:
                continue
            ratio = len(carried) / len(readers)
            if ratio < MIN_RATIO:
                continue
            groups += 1
            for h in readers:
                if guard in h["decs"]:
                    continue
                findings.append({
                    "tool": "blind", "rule": "authz/guard-inconsistent-with-peers",
                    "file": h["file"], "line": h["line"],
                    "sev": "INFO", "advisory": True,
                    "message": (f"{h['verb']} {h['path']} reads `{model}` like the "
                                f"{len(readers)} other handlers that do, and "
                                f"{len(carried)} of them carry `@{guard}` while this one "
                                f"does not"),
                    "remedy": (f"confirm whether this endpoint is meant to be reachable by "
                               f"callers `@{guard}` would refuse; if it is, declare it so "
                               f"the omission becomes a recorded decision"),
                    "evidence": {"guard": guard, "model": model, "readers": len(readers),
                                 "carried": len(carried), "ratio": round(ratio, 2)},
                })
    # one finding per site, keeping the best-supported explanation
    best = {}
    for f in findings:
        k = (f["file"], f["line"])
        if k not in best or f["evidence"]["ratio"] > best[k]["evidence"]["ratio"]:
            best[k] = f
    return list(best.values()), {"handlers": len(hs), "model_groups": groups,
                                 "guards_that_refuse": len(can_refuse)}


def discover(root):
    """Anomalies relative to the project's own practice. Advisory by construction.

    TWO TESTS, AND WHY BOTH ARE NEEDED
    A guard must (a) be able to refuse, which is read from its own definition and is
    framework-independent, and (b) name the thing it protects, which is a convention about how
    authorization decorators are written rather than a fact about this project's data. (a)
    alone admits `@doc`, a documentation decorator applied to thirteen of fifteen peers in one
    of our subjects, because consistency by itself cannot tell a security convention from any
    other. (b) alone admits anything with the right name and no teeth.

    The limitation this leaves is stated rather than tuned away: peers are grouped by whether
    the protected noun appears joined to an identity attribute in what the handler can reach,
    within one call hop. That is a proxy for the thing actually wanted, which is the shape of
    the response. Grouping on the response, by resolving each handler's serialiser or
    projection, would drop the naming convention in (b) entirely, and is the next piece of
    work rather than something a threshold can fix.
    """
    hs = _handlers(root)
    if len(hs) < MIN_PEERS:
        return [], {"handlers": len(hs), "reason": "too few handlers to infer a convention"}

    helper_idx = FR._helper_index(root)
    can_refuse = _guards(root, helper_idx)

    # a guard is a decorator that can refuse AND declares what it protects
    fams = {}
    for h in hs:
        for d in h["decs"]:
            if d not in can_refuse:
                continue
            noun = FR._guard_noun(d) if hasattr(FR, "_guard_noun") else _noun(d)
            if noun:
                fams.setdefault((d, noun), []).append(h)

    findings, considered = [], 0
    for (guard, noun), carriers in sorted(fams.items()):
        if len(carriers) < MIN_CARRIERS:
            continue
        considered += 1
        for h in hs:
            if h["verb"] not in READ_VERBS or guard in h["decs"]:
                continue
            if h["decs"] & DOMINATING:
                continue
            if not any(f"{noun}_{a}" in h["reach"] for a in IDENTITY_ATTRS):
                continue
            findings.append({
                "tool": "blind", "rule": "authz/guard-inconsistent-with-peers",
                "file": h["file"], "line": h["line"],
                "sev": "INFO", "advisory": True,          # blind findings never gate
                "message": (f"{h['verb']} {h['path']} reaches {noun} identity and does not "
                            f"carry `@{guard}`, which this project applies to "
                            f"{len(carriers)} other handlers"),
                "remedy": (f"confirm whether {h['cls']}.{h['verb'].lower()} is meant to be "
                           f"reachable by callers `@{guard}` would refuse. If it is not, "
                           f"apply the guard; if it is, declare it so the omission becomes a "
                           f"recorded decision rather than an oversight"),
                "evidence": {"guard": guard, "noun": noun, "carriers": len(carriers),
                             "refuses": True},
            })
    return findings, {"handlers": len(hs), "guards_that_refuse": len(can_refuse),
                      "conventions_found": considered}


def _fmt(root):
    f, meta = discover(root)
    print(f"{len(f)} blind finding(s)   [{meta}]")
    for x in f:
        print(f"  {x['file']}:{x['line']}  {x['message']}")
        print(f"     evidence: {x['evidence']}")
    return f


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--calibrate" in sys.argv:
        # Firing rate on third-party code the rule was not written for. A consistency rule is
        # only shippable if this is near zero; the number, not the intuition, admits the rule.
        tot_f = tot_h = 0
        for d in sorted(args):
            f, meta = discover(d)
            tot_f += len(f)
            tot_h += meta.get("handlers", 0)
            print(f"  {os.path.basename(d.rstrip('/')):<30} handlers={meta.get('handlers',0):<5} "
                  f"findings={len(f)}")
        print(f"\n  {tot_f} finding(s) over {tot_h} handlers in {len(args)} project(s)")
        sys.exit(0)
    _fmt(args[0] if args else ".")
