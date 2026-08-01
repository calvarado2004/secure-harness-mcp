#!/usr/bin/env python3
"""An authorization lane for flask-restx: the same rules, a route form no lane could read.

WHY THIS IS A MODULE AND NOT AN EDIT TO THE FLASK LANE
The Flask lane walks decorated FUNCTIONS. flask-restx puts the path on a CLASS and the verb
in the METHOD NAME:

    @challenges_namespace.route("/<challenge_id>/solves")
    class ChallengeSolves(Resource):
        def get(self, challenge_id): ...

To a lane that only walks decorated functions that file contains no routes, so it is opened,
parsed, and reported clean. On the subject this module was written for that is 125 handlers
across 21 namespaces, an entire REST API, invisible to the axis meant to read it while
`bandit` reads the same files and finds nothing, because a missing authorization decorator is
not a pattern it can express.

It is a module because packs are opt-in per project: a profile that does not name this
framework does not load it, so subjects already measured keep their instrument by
construction rather than by promise.

THE RULE THIS ADDS, AND WHY IT IS NOT "NO AUTHORIZATION"
The handler that motivated this module reads the caller's identity, carries two visibility
guards, and is still a published CVE. What it omits is the third guard, the one its own
project applies to every other handler returning the same class of data. Every rule that asks
"does this handler check anything?" answers yes.

So the question is not whether a guard is present but whether the guard THIS PROJECT uses for
THIS DATA CLASS is present. That splits into two parts, and only one of them is a fact anyone
has to supply:

  SUPPLIED (profile)  which data class is not public, and which attributes disclose it.
                      This is a policy: "account identity is not public, and a handler
                      discloses it by projecting a name, username or email off an account".
                      It names no endpoint.

  INFERRED (this lane) which decorator the project uses to enforce that policy, how widely it
                      is established, and WHICH HANDLER DEVIATES. The lane reads the guard's
                      carriers out of the repository and finds the omission itself.

That division is the point. A rule told which endpoint is broken proves nothing; a rule told
what the project's policy is, and left to find the site, is a rule that generalises.

THREE RESTRICTIONS, EACH ONE A DEFECT CLASS IT REFUSES TO INVENT
  * CORROBORATION. A guard must already be carried by several handlers before its absence
    anywhere means anything. One handler carrying a decorator is a coincidence, not a
    convention, and a lane that infers a convention from noise reports conformant code.
  * DOMINANCE. A handler restricted to administrators does not also need a visibility guard;
    the stronger guard subsumes the weaker. Without this the lane flags every admin endpoint
    that touches the protected data.
  * READS ONLY. A visibility guard controls disclosure, so it is asked of handlers that
    RETURN the data. A write that happens to touch the same table is not a disclosure, and
    flagging it spends a repair round on an endpoint that discloses nothing.

WHAT IT DELIBERATELY DOES NOT DO
It does not claim the inconsistency is exploitable; the behavioural battery decides that. It
does not model role hierarchies beyond the dominance list the profile supplies. Where the
project has not established a guard, it says nothing rather than guessing.
"""
import ast
import copy
import os
import re
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images", "migrations"}
VERBS = {"get", "post", "put", "delete", "patch"}
READ_VERBS = {"GET"}

# How much of a project's own practice counts as a convention. Deliberately not 1.
MIN_CARRIERS = 3

# Guards whose NAME announces the noun they protect. Used only to infer which decorator
# enforces a policy the profile has already declared; never to invent a policy.
GUARD_PATTERNS = (
    re.compile(r"^check_(?P<noun>[a-z0-9]+)_visibility$"),
    re.compile(r"^require_(?P<noun>[a-z0-9]+)_access$"),
    re.compile(r"^(?P<noun>[a-z0-9]+)_visibility_required$"),
)


def _py_files(root):
    if os.path.isfile(root):
        return [root]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def _parse(path):
    try:
        return ast.parse(open(path, encoding="utf8", errors="replace").read())
    except SyntaxError:
        return None


def restx_mounts(root):
    """Where each Namespace is mounted, so a handler reports a path a caller can reach.

    `@challenges_namespace.route("/<id>/solves")` is not reachable at that string: the
    namespace is added to an Api under a prefix and the Api hangs off a Blueprint with a
    url_prefix. Report the fragment and every declared-intent lookup misses, so a project
    could declare a route public and the lane would still ask about it.
    """
    mounts, prefixes = {}, []
    for path in _py_files(root):
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name == "Blueprint":
                for kw in node.keywords:
                    if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant):
                        prefixes.append(kw.value.value)
            elif name == "add_namespace" and node.args:
                var = getattr(node.args[0], "id", None)
                sub = (node.args[1].value
                       if len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                       else "")
                if var:
                    mounts[var] = sub
    base = max(prefixes, key=len) if prefixes else ""
    return {v: base + s for v, s in mounts.items()}


def _decorator_names(node):
    out = set()
    for d in node.decorator_list:
        n = d.func if isinstance(d, ast.Call) else d
        name = getattr(n, "id", None) or getattr(n, "attr", None)
        if name:
            out.add(name)
    return out


def restx_handlers(tree, mounts):
    """(verb, path, methodnode, classname) for every Resource method in this tree.

    Decorators on the CLASS are copied onto each method: flask-restx applies them to every
    verb the Resource serves, so a class carrying `@admins_only` guards each method even
    though no method spells it.
    """
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        route, others = None, []
        for dec in node.decorator_list:
            fn = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(dec, ast.Call) and getattr(fn, "attr", None) == "route":
                route = dec
            else:
                others.append(dec)
        if route is None:
            continue
        ns = getattr(getattr(route.func, "value", None), "id", None)
        sub = (route.args[0].value
               if route.args and isinstance(route.args[0], ast.Constant) else "")
        path = mounts.get(ns, "") + sub
        for item in node.body:
            if (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name.lower() in VERBS):
                m = copy.copy(item)
                m.decorator_list = list(others) + list(item.decorator_list)
                out.append((item.name.upper(), path, m, node.name))
    return out


def _called_names(func):
    out = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Call):
            name = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            if name:
                out.add(name)
    return out


def _tokens(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id.lower())
        elif isinstance(n, ast.Attribute):
            out.add(n.attr.lower())
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.add(n.value.lower())
        elif isinstance(n, ast.keyword) and n.arg:
            out.add(n.arg.lower())
    return out


def _helper_index(root):
    """Every function in the repo, so a handler's disclosure can follow one call hop.

    The handler that motivated this module returns nothing identifying on its own face: it
    calls `get_solves_for_challenge_id(...)` and returns the result. The account name it
    discloses is selected inside that helper, which is how a lane can open a file, parse it,
    and still be wrong about what the endpoint returns.
    """
    index = {}
    for path in _py_files(root):
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index.setdefault(node.name, []).append(node)
    return index


def _reach(func, helpers):
    toks = _tokens(func)
    for name in _called_names(func):
        for defn in helpers.get(name, [])[:2]:       # one hop, not a whole call graph
            toks |= _tokens(defn)
    return toks


def _guard_for(noun, handlers, declared=None):
    """Which decorator this project uses to protect `noun`, and how established it is."""
    if declared:
        carriers = [h for h in handlers if declared in h["decs"]]
        return declared, carriers
    best, best_carriers = None, []
    for h in handlers:
        for d in h["decs"]:
            for pat in GUARD_PATTERNS:
                m = pat.match(d)
                if m and m.group("noun") == noun:
                    carriers = [x for x in handlers if d in x["decs"]]
                    if len(carriers) > len(best_carriers):
                        best, best_carriers = d, carriers
    return best, best_carriers


def scan_flask_restx_authz(root, facts=None):
    """Findings for flask-restx handlers. Returns (findings, unparsed_or_None).

    `facts` is the profile's declaration, e.g.
        {"protected_data": [{"noun": "account",
                             "identity_attrs": ["name", "username", "email"],
                             "guard": "check_account_visibility"}],   # optional
         "dominating_guards": ["admins_only"]}
    With no protected_data the lane reads the route surface and reports nothing, which is the
    correct answer to "is this authorized?" from a project that has not said what is private.
    """
    root = os.path.abspath(root)
    facts = facts or {}
    protected = facts.get("protected_data") or []
    dominating = set(facts.get("dominating_guards") or ["admins_only"])

    mounts = restx_mounts(root)
    helpers = _helper_index(root)
    handlers = []
    for path in _py_files(root):
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        tree = _parse(path)
        if tree is None:
            return None, rel                 # unparseable: no answer, not "no findings"
        for verb, route, func, cls in restx_handlers(tree, mounts):
            handlers.append({"verb": verb, "path": route or "/", "func": func, "cls": cls,
                             "file": rel, "decs": _decorator_names(func),
                             "reach": _reach(func, helpers)})

    findings = []
    for spec in protected:
        noun = (spec.get("noun") or "").lower()
        attrs = [a.lower() for a in (spec.get("identity_attrs") or [])]
        if not noun or not attrs:
            continue
        guard, carriers = _guard_for(noun, handlers, spec.get("guard"))
        if not guard or len(carriers) < MIN_CARRIERS:
            continue                          # no established convention, so no verdict

        for h in handlers:
            if h["verb"] not in READ_VERBS:            # a write is not a disclosure
                continue
            if h["decs"] & dominating:                 # a stronger guard subsumes this one
                continue
            if guard in h["decs"]:
                continue
            if not any(f"{noun}_{a}" in h["reach"] for a in attrs):
                continue
            findings.append({
                "tool": "authz", "rule": "authz/guard-inconsistent-with-peers",
                "file": h["file"], "line": h["func"].lineno,
                "sev": "HIGH", "advisory": False,
                "message": (
                    f"{h['verb']} {h['path']} discloses {noun} identity but does not carry "
                    f"`@{guard}`, which this project applies to {len(carriers)} other "
                    f"handlers"),
                "remedy": (
                    f"apply `@{guard}` to {h['cls']}.{h['func'].name.lower()} as the "
                    f"{len(carriers)} sibling handlers do. If this endpoint is meant to "
                    f"disclose {noun} identity to callers that guard would refuse, declare "
                    f"that rather than leaving it to omission"),
                "evidence": {"guard": guard, "noun": noun, "carriers": len(carriers),
                             "peers": sorted({c["file"] for c in carriers})[:4]},
            })
    return findings, None


# The controls carry their own policy, because a control that needed the subject's profile
# would be testing the profile.
CONTROL_FACTS = {"protected_data": [{"noun": "account",
                                     "identity_attrs": ["name", "username", "email"]}],
                 "dominating_guards": ["admins_only"]}


def _selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    pack = os.path.join(here, "..", "packs", "python", "authorization", "flask-restx")
    ok = True
    for kind, expect in (("positive", True), ("negative", False)):
        d = os.path.join(pack, "controls", kind)
        found, unparsed = scan_flask_restx_authz(d, CONTROL_FACTS)
        hit = bool(found)
        good = (hit == expect) and unparsed is None
        ok &= good
        print(f"[{'PASS' if good else 'FAIL'}] {kind}: {len(found or [])} finding(s), "
              f"expected {'>=1' if expect else '0'}")
    # A lane that fires without a policy would be inventing one.
    found, _ = scan_flask_restx_authz(os.path.join(pack, "controls", "positive"), {})
    ok &= not found
    print(f"[{'PASS' if not found else 'FAIL'}] no-policy: {len(found or [])} finding(s), "
          f"expected 0 (a project that declares nothing gets no verdict)")
    print("all flask-restx lane controls passed" if ok else "CONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    found, unparsed = scan_flask_restx_authz(args[0] if args else ".", CONTROL_FACTS)
    if unparsed:
        print(f"UNMEASURED: {unparsed} does not parse")
        sys.exit(2)
    print(f"{len(found)} authorization findings")
    for f in found:
        print(f"  [{f['sev']:6s}] {f['rule']:36s} {f['file']}:{f['line']}")
        print(f"           {f['message']}")
