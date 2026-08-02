#!/usr/bin/env python3
"""An authorization lane for flask-restful: a third mounting form, and a write-side rule.

WHY THIS IS A THIRD MODULE AND NOT AN EDIT TO EITHER EXISTING FLASK LANE

The Flask lane walks decorated FUNCTIONS (`@app.route`). The flask-restx lane walks classes
carrying a route DECORATOR (`@ns.route(...)`). flask-restful does neither: the class is bare
and the path arrives later, in a CALL:

    class Roles(AuthenticatedResource):
        def get(self, role_id): ...
        def put(self, role_id, data=None): ...
    ...
    api.add_resource(Roles, "/roles/<int:role_id>", endpoint="role")

To both existing lanes that file contains no routes. Measured on the subject this module was
written for, the entire REST API reduced to **one** handler and **zero** mounts, and the
profile-free consistency primitive correctly declined to infer a convention from a single
handler. The rules were never given the chance to be wrong; the parser could not see the code.
That is the third distinct mounting mechanism in one language, and it is why this file exists.

WHAT IS BORROWED AND WHAT IS NEW, STATED SO AN AUDITOR CAN CHECK IT

Everything that DECIDES anything is imported from `flask_restx_authz` and used unmodified:
`_decorator_names`, `_helper_index`, `_reach`, `_guard_for`, `MIN_CARRIERS`. This module
supplies handler DISCOVERY and nothing else for the read rule, so
`authz/guard-inconsistent-with-peers` on a flask-restful project is the same rule, byte for
byte, as on a flask-restx one. `assert_rule_logic_unchanged()` re-checks that at runtime
against a recorded digest, and the self-test calls it.

ONE RULE IS GENUINELY NEW, AND IT IS NOT A PARSER CHANGE

The inherited rule asks about DISCLOSURE, so it considers read verbs only: a write that
touches protected data is not a disclosure, and flagging it spends a repair round on an
endpoint that reveals nothing. That restriction is right for the class of defect it was
written for and blind to another one:

    a handler that MUTATES a resource whose siblings on the same path are
    administrator-only, and which carries no comparable guard itself

is not a disclosure defect; it is a privilege defect. On the motivating subject, `post` and
`delete` on the same resource both carry the project's administrator guard and `put` carries
none, so any member of a role could rewrite that role's membership. No read rule can express
that, because nothing is being read.

`authz/mutation-guard-weaker-than-siblings` is therefore reported as a NEW rule id and never
folded into the inherited one. Its evidence names the sibling handlers whose guards it is
comparing against, so a reader can check the inference rather than trust it.

THE RESTRICTIONS IT KEEPS

  * TWO TESTS, BOTH REQUIRED. Repository first: the guard must be carried by MIN_CARRIERS
    handlers, so it is the project's convention and not one author's habit. Resource second:
    a sibling mounted at the SAME path must carry it while this handler does not, so the
    project has stated a rule about this resource and this handler departs from it. A
    repository-wide count alone would flag every deliberately-public collection endpoint; a
    sibling count alone would promote any shared decorator into a security convention.
  * A GUARD MUST NAME ITSELF ONE. Only decorators whose name says they decide access are
    considered. The first run of this lane, without that test, reported a DELETE handler for
    omitting `validate_schema` -- a request-body validator two of its siblings happened to
    share. A schema validator is not an authorization decision.
  * DOMINANCE. A handler already carrying a guard at least as strong as its siblings' is
    conformant, whatever else it omits.
  * IT CLAIMS NO EXPLOIT. Whether the deviation is reachable is the behavioural battery's
    question, not this lane's.

WHAT IT DELIBERATELY DOES NOT DO

It does not infer a policy from an undeclared project: with no `protected_data` in the profile
the inherited read rule returns nothing, exactly as it does elsewhere. The sibling rule needs
no profile because it reads a decision the project already wrote down in code, which is the
same argument `blind_consistency` rests on.
"""
import ast
import copy
import hashlib
import inspect
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask_restx_authz import (          # noqa: E402  — every decision function, unmodified
    MIN_CARRIERS,
    _decorator_names,
    _guard_for,
    _helper_index,
    _parse,
    _py_files,
    _reach,
)

VERBS = {"get", "post", "put", "delete", "patch"}
READ_VERBS = {"GET"}
MUTATING_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

# A decorator is a candidate GUARD only if its name says it decides access. Without this the
# rule counts any decorator two siblings happen to share -- the first run of it reported
# `validate_schema`, a request-body validator, as the convention a DELETE handler was
# violating. A schema validator is not an authorization decision and a lane that cannot tell
# the difference manufactures findings on every well-factored codebase.
GUARD_NAME = re.compile(
    r"(^|[._])(permission|permissions|require|requires|required|admins?_only|"
    r"roles?_(accepted|required)|login_required|auth|authorize|authorized|authenticated)"
    r"([._]|$)", re.I)

# Repository-wide corroboration for the guard itself, reusing MIN_CARRIERS' reasoning: a
# decorator two handlers share is a coincidence; one that guards this many is the project's
# convention. Checked BEFORE any sibling comparison.
# At least this many siblings on the same path must carry it before an omission means
# anything locally. One is enough here only because the repository-wide test above has
# already established that the guard is a convention.
MIN_GUARDED_SIBLINGS = 1

# Digest of the imported decision functions, recorded when this module was written. If a later
# edit to flask_restx_authz changes what those functions decide, this stops matching and the
# claim "the read rule is byte-identical across the two mounting forms" stops being asserted.
_BORROWED = (_decorator_names, _guard_for, _reach, _helper_index)


def rule_logic_digest():
    h = hashlib.sha256()
    for fn in _BORROWED:
        h.update(inspect.getsource(fn).encode())
    h.update(str(MIN_CARRIERS).encode())
    return h.hexdigest()[:16]


RULE_LOGIC_DIGEST = "6f03d4862fec47de"   # set by --print-digest; see the self-test


def assert_rule_logic_unchanged():
    got = rule_logic_digest()
    if got != RULE_LOGIC_DIGEST:
        raise AssertionError(
            f"borrowed rule logic changed: expected {RULE_LOGIC_DIGEST}, got {got}. "
            "The read rule is no longer identical to the flask-restx lane's; either revert "
            "the edit or stop claiming they are the same rule.")
    return True


# --------------------------------------------------------------------------------------
# Discovery: the only thing this module adds for the inherited rule.
# --------------------------------------------------------------------------------------

def restful_mounts(root):
    """{class name: url path} from `api.add_resource(Cls, "/path", ...)`.

    The Api hangs off a Blueprint with a url_prefix, so the fragment on its own is not a path
    a caller can reach; the longest declared prefix is prepended for the same reason the
    flask-restx lane does it, so that declared-intent lookups match real routes.
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
            elif name == "add_resource" and len(node.args) >= 2:
                cls = getattr(node.args[0], "id", None)
                for arg in node.args[1:]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if cls:
                            mounts.setdefault(cls, []).append(arg.value)
    base = max(prefixes, key=len) if prefixes else ""
    return {c: [base + p for p in ps] for c, ps in mounts.items()}


def restful_handlers(tree, mounts):
    """(verb, path, methodnode, classname) for every mounted Resource method in this tree.

    Class decorators are copied onto each method, as in the flask-restx lane: a guard on the
    class guards every verb the resource serves even though no method spells it.
    """
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name not in mounts:
            continue
        others = list(node.decorator_list)
        for path in mounts[node.name]:
            for item in node.body:
                if (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name.lower() in VERBS):
                    m = copy.copy(item)
                    m.decorator_list = others + list(item.decorator_list)
                    out.append((item.name.upper(), path, m, node.name))
    return out


def _dotted_decorators(node):
    """Full dotted decorator names, e.g. `admin_permission.require`.

    The imported `_decorator_names` keeps the last attribute only, which is right for the
    read rule and unreadable in a message: it renders `@admin_permission.require(...)` as
    "require", so the finding said a handler "requires require". This is used for naming and
    for the guard-name test; it never changes what the inherited read rule decides.
    """
    out = set()
    for d in node.decorator_list:
        n = d.func if isinstance(d, ast.Call) else d
        parts = []
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
        if parts:
            out.add(".".join(reversed(parts)))
    return out


def collect(root):
    """All handlers, or (None, unparsed_rel_path). Shared by both rules."""
    root = os.path.abspath(root)
    mounts = restful_mounts(root)
    helpers = _helper_index(root)
    handlers = []
    for path in _py_files(root):
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        tree = _parse(path)
        if tree is None:
            return None, rel                  # unparseable: no answer, not "no findings"
        for verb, route, func, cls in restful_handlers(tree, mounts):
            handlers.append({"verb": verb, "path": route or "/", "func": func, "cls": cls,
                             "file": rel, "line": func.lineno,
                             "decs": _decorator_names(func),
                             "dotted": _dotted_decorators(func),
                             "reach": _reach(func, helpers)})
    return handlers, None


# --------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------

def _read_rule(handlers, facts):
    """authz/guard-inconsistent-with-peers, using the flask-restx decision functions."""
    findings = []
    for spec in (facts.get("protected_data") or []):
        noun = (spec.get("noun") or "").lower()
        attrs = [a.lower() for a in (spec.get("identity_attrs") or [])]
        if not noun or not attrs:
            continue
        guard, carriers = _guard_for(noun, handlers, spec.get("guard"))
        if not guard or len(carriers) < MIN_CARRIERS:
            continue
        dominating = set(facts.get("dominating_guards") or ["admins_only"])
        for h in handlers:
            if h["verb"] not in READ_VERBS or h["decs"] & dominating or guard in h["decs"]:
                continue
            if not any(f"{noun}_{a}" in h["reach"] for a in attrs):
                continue
            findings.append({
                "tool": "authz", "rule": "authz/guard-inconsistent-with-peers",
                "file": h["file"], "line": h["line"], "sev": "HIGH", "advisory": False,
                "message": (f"{h['verb']} {h['path']} discloses {noun} identity and does not "
                            f"carry {guard}, which {len(carriers)} sibling handlers do"),
                "remedy": f"apply {guard} to this handler",
            })
    return findings


def _guards_of(h):
    """The access-deciding decorators on a handler, by name. Not every decorator counts."""
    return {d for d in h.get("dotted", h["decs"]) if GUARD_NAME.search(d)}


def _sibling_rule(handlers, facts):
    """authz/mutation-guard-weaker-than-siblings — new here; see the module docstring.

    Two independent tests must both pass before anything is reported:
      1. REPOSITORY. The guard is carried by at least MIN_CARRIERS handlers, so it is the
         project's convention rather than one author's habit.
      2. RESOURCE. At least MIN_GUARDED_SIBLINGS handlers mounted at the SAME path carry it
         while this one does not, so the project has stated a rule about this resource and
         this handler departs from it.
    """
    dominating = set(facts.get("dominating_guards") or [])

    # 1. repository-wide corroboration
    carriers = {}
    for h in handlers:
        for g in _guards_of(h):
            carriers[g] = carriers.get(g, 0) + 1
    established = {g for g, n in carriers.items() if n >= MIN_CARRIERS}
    if not established:
        return []

    by_path = {}
    for h in handlers:
        by_path.setdefault(h["path"], []).append(h)

    seen, findings = set(), []
    for path, group in sorted(by_path.items()):
        muts = [h for h in group if h["verb"] in MUTATING_VERBS]
        if len(muts) < 2:
            continue
        # 2. what this resource's own siblings establish
        local = {}
        for h in muts:
            for g in _guards_of(h) & established:
                local[g] = local.get(g, 0) + 1
        convention = {g for g, n in local.items() if n >= MIN_GUARDED_SIBLINGS}
        if not convention:
            continue
        for h in muts:
            if _guards_of(h) & convention or h.get("dotted", h["decs"]) & dominating:
                continue
            key = (h["file"], h["line"], h["cls"])
            if key in seen:          # one class may be mounted at several paths
                continue
            seen.add(key)
            carried = sorted(convention)
            peers = sorted({s["verb"] for s in muts if _guards_of(s) & convention})
            findings.append({
                "tool": "authz", "rule": "authz/mutation-guard-weaker-than-siblings",
                "file": h["file"], "line": h["line"], "sev": "HIGH", "advisory": False,
                "message": (f"{h['verb']} {path} mutates a resource whose {', '.join(peers)} "
                            f"sibling(s) carry {', '.join(carried)}, and it carries no "
                            f"comparable guard"),
                "remedy": (f"apply {carried[0]} to this handler, or record why this verb is "
                           f"deliberately less restricted than its siblings"),
                "evidence": {"path": path, "class": h["cls"], "convention": carried,
                             "guarded_siblings": peers,
                             "repo_carriers": {g: carriers[g] for g in carried}},
            })
    return findings


def scan_flask_restful_authz(root, facts=None):
    """Findings for flask-restful handlers. Returns (findings, unparsed_or_None)."""
    facts = facts or {}
    handlers, unparsed = collect(root)
    if handlers is None:
        return None, unparsed
    return _read_rule(handlers, facts) + _sibling_rule(handlers, facts), None


# --------------------------------------------------------------------------------------

def _selftest():
    import tempfile
    ok = assert_rule_logic_unchanged()
    print("[PASS] borrowed rule logic is byte-identical to the flask-restx lane")

    # `require` must be carried by MIN_CARRIERS handlers before it counts as the project's
    # convention, so the fixture establishes it across three resources -- the same bar the
    # inherited read rule applies. `Gadgets` supplies the third carrier and is otherwise
    # conformant; `Public` establishes nothing and must stay silent.
    src = '''
from flask import Blueprint
from flask_restful import Api
mod = Blueprint("mod", __name__, url_prefix="/api/1")
api = Api(mod)

class Widgets(Resource):
    @admin_permission.require(http_exception=403)
    def post(self, widget_id): ...
    def put(self, widget_id): ...
    @admin_permission.require(http_exception=403)
    def delete(self, widget_id): ...
    def get(self, widget_id): ...

class Gadgets(Resource):
    @admin_permission.require(http_exception=403)
    def post(self): ...
    @admin_permission.require(http_exception=403)
    def delete(self): ...

class Public(Resource):
    def post(self): ...
    def put(self): ...
    def delete(self): ...

class Validated(Resource):
    @validate_schema(gizmo_input, gizmo_output)
    def post(self, gizmo_id): ...
    @validate_schema(gizmo_input, gizmo_output)
    def put(self, gizmo_id): ...
    def delete(self, gizmo_id): ...

api.add_resource(Widgets, "/widgets/<int:widget_id>")
api.add_resource(Gadgets, "/gadgets")
api.add_resource(Public, "/public")
api.add_resource(Validated, "/gizmos/<int:gizmo_id>")
'''
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "views.py"), "w").write(src)
        f, un = scan_flask_restful_authz(td)

        mounts = restful_mounts(td)
        good = mounts.get("Widgets") == ["/api/1/widgets/<int:widget_id>"]
        print(("[PASS] " if good else "[FAIL] ")
              + f"add_resource mounting resolves under the blueprint prefix: {mounts}")
        ok = ok and good

        sib = [x for x in f if x["rule"] == "authz/mutation-guard-weaker-than-siblings"]
        hit = len(sib) == 1 and sib[0]["evidence"]["class"] == "Widgets" \
            and sib[0]["message"].startswith("PUT ")
        print(("[PASS] " if hit else "[FAIL] ")
              + f"the unguarded PUT among guarded siblings is named, and only it "
                f"({[(x['evidence']['class'], x['message'].split()[0]) for x in sib]})")
        ok = ok and hit

        quiet = not any(x["evidence"]["path"] == "/api/1/public" for x in sib)
        print(("[PASS] " if quiet else "[FAIL] ")
              + "a resource whose siblings establish no guard raises nothing")
        ok = ok and quiet

        # The defect this control exists for: `validate_schema` is shared by two mutating
        # siblings and is not an authorization decision. Counting it made the first run of
        # this lane report a DELETE handler that was never unguarded.
        noval = not any(x["evidence"]["class"] == "Validated" for x in sib)
        print(("[PASS] " if noval else "[FAIL] ")
              + "a non-security decorator shared by siblings is not mistaken for a guard")
        ok = ok and noval

        noread = not [x for x in f if x["rule"] == "authz/guard-inconsistent-with-peers"]
        print(("[PASS] " if noread else "[FAIL] ")
              + "with no profile the inherited read rule stays silent")
        ok = ok and noread

    # Two more paired controls on variants of the same fixture.
    src2 = src.replace("    def put(self, widget_id): ...",
                       "    @admin_permission.require(http_exception=403)\n"
                       "    def put(self, widget_id): ...")
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "views.py"), "w").write(src2)
        f2, _ = scan_flask_restful_authz(td)
        conform = not [x for x in f2 if x["rule"] == "authz/mutation-guard-weaker-than-siblings"]
        print(("[PASS] " if conform else "[FAIL] ")
              + "a conformant resource raises nothing (the paired negative control)")
        ok = ok and conform

    # Under-corroborated guard: drop Gadgets and `require` has only 2 carriers repo-wide,
    # below MIN_CARRIERS, so no convention exists and the same PUT must NOT be reported.
    src3 = src[:src.index("class Gadgets")] + src[src.index("class Public"):]
    src3 = src3.replace('api.add_resource(Gadgets, "/gadgets")\n', "")
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "views.py"), "w").write(src3)
        f3, _ = scan_flask_restful_authz(td)
        few = not [x for x in f3 if x["rule"] == "authz/mutation-guard-weaker-than-siblings"]
        print(("[PASS] " if few else "[FAIL] ")
              + f"a guard with fewer than MIN_CARRIERS={MIN_CARRIERS} carriers establishes "
                f"no convention, so the same PUT raises nothing")
        ok = ok and few

    # Unparseable input must be reported as unmeasured, never as clean.
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "broken.py"), "w").write("def f(:\n")
        f4, un4 = scan_flask_restful_authz(td)
        meas = f4 is None and un4 == "broken.py"
        print(("[PASS] " if meas else "[FAIL] ")
              + f"a file that does not parse reads as unmeasured, not clean ({un4})")
        ok = ok and meas

    print("\nall flask-restful lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--print-digest" in sys.argv:
        print(rule_logic_digest())
    elif "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    else:
        import json
        facts = {}
        if "--facts" in sys.argv:
            facts = json.load(open(sys.argv[sys.argv.index("--facts") + 1]))
        f, un = scan_flask_restful_authz(sys.argv[1], facts)
        if f is None:
            print(json.dumps({"unparsed": un}))
        else:
            print(f"{len(f)} finding(s)")
            for x in f:
                print(f"  {x['rule']}  {x['file']}:{x['line']}  {x['sev']}")
                print(f"    {x['message']}")
