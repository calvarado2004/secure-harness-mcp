#!/usr/bin/env python3
"""Policy-free gotchas: the defects no project's trust boundaries can make correct.

WHY THIS TIER EXISTS SEPARATELY
Most of this harness answers questions that need a project to speak first. "Is this endpoint
authorized?" depends on who may see what, which lives in the project and not in its syntax, so
those lanes correctly say nothing about a repository nobody has described. That is right for
repair and useless for the first thing a practitioner does, which is point the tool at
unfamiliar code.

Some defects need no such declaration. No trust boundary makes a browser credential readable
by any script correct, and no deployment makes a wildcard origin with credentials attached
safe. Those are decidable from the file alone, which is what lets this tier run anywhere.

WHAT IT DELIBERATELY DOES NOT DUPLICATE
`bandit` and Semgrep already find hardcoded secrets, `debug=True`, disabled TLS verification,
pickle on untrusted input and shell interpolation, and running a worse copy of them helps
nobody. Measured against both engines on a file carrying four of these classes, they each
found two, the hardcoded key and the debug flag, and missed the other two entirely. Those two
are what this module adds.

DEPLOYMENT CONTEXT IS PART OF THE FINDING
A credential in `.devcontainer/tests/docker-compose.yaml` is a fixture, not a shipped default.
Across eight third-party repositories every policy-free finding raised before this distinction
existed was of that kind. A file that only ever describes a developer's laptop is reported for
review and never gated, because a tool that cannot tell a test fixture from a deployment
teaches its reader to skim the axis.
"""
import ast
import os
import re
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build",
             "migrations", "site-packages"}
# Paths whose contents describe a developer's machine rather than a deployment.
DEV_PARTS = {".devcontainer", "tests", "test", "examples", "example", "docs", "fixtures",
             "e2e", "ci", ".github", "contrib", "sandbox", "demo"}
DEV_NAME = ("dev", "test", "local", "example", "sample", "conftest")


def _dev_only(rel):
    parts = {p.lower() for p in rel.replace("\\", "/").split("/")[:-1]}
    if parts & DEV_PARTS:
        return True
    name = rel.replace("\\", "/").split("/")[-1].lower()
    return any(k in name for k in DEV_NAME)


def _py_files(root):
    if os.path.isfile(root):
        return [root]
    out = []
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        out += [os.path.join(dp, f) for f in sorted(fns) if f.endswith(".py")]
    return out


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _wildcard(node):
    """Is this expression a wildcard origin, however it is spelled?"""
    v = _const(node)
    if v == "*":
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_const(e) == "*" for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_wildcard(v2) for v2 in node.values)
    return False


def _truthy(node):
    return _const(node) is True


# ---------------------------------------------------------------------------
def _cors(tree, rel):
    """Wildcard origin together with credentials.

    The browser will not honour `Access-Control-Allow-Origin: *` when credentials are
    attached, so a framework asked for both emits the CALLER'S origin instead and the
    restriction disappears: any site a victim visits can call the API with their cookies. This
    is the first link in a published account-takeover chain in a widely deployed AI workflow
    platform, and neither commodity engine flags it.
    """
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        fname = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
        if fname not in ("CORS", "add_middleware", "CORSMiddleware"):
            continue
        origins = (_kw(n, "origins") or _kw(n, "allow_origins")
                   or _kw(n, "resources") or (n.args[1] if len(n.args) > 1 else None))
        creds = _kw(n, "supports_credentials") or _kw(n, "allow_credentials")
        if origins is not None and _wildcard(origins) and creds is not None and _truthy(creds):
            out.append({
                "tool": "gotcha", "rule": "cors/wildcard-with-credentials",
                "file": rel, "line": n.lineno, "sev": "HIGH",
                "message": ("cross-origin requests are accepted from any origin AND carry "
                            "credentials, so any site the victim visits can call this API "
                            "with their session"),
                "remedy": ("list the origins that may send credentialed requests, or drop "
                           "credentials; a wildcard and credentials cannot both hold"),
            })
    return out


def _cookies(tree, rel):
    """A session cookie readable by script, or sent in clear.

    Flask and Django both default these to safe values and both are routinely turned off
    during development and left off. `HttpOnly` false puts the session token within reach of
    any injected script; `Secure` false sends it over plain HTTP. Neither commodity engine
    reads configuration assignments of this shape.
    """
    out = []
    flags = {"SESSION_COOKIE_HTTPONLY": "readable by any script in the page",
             "SESSION_COOKIE_SECURE": "sent over unencrypted connections",
             "CSRF_COOKIE_SECURE": "sent over unencrypted connections",
             "SESSION_COOKIE_SAMESITE": None}
    for n in ast.walk(tree):
        key = val = None
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Subscript):
            key = _const(n.targets[0].slice)
            val = n.value
        elif isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
            key, val = n.targets[0].id, n.value
        elif isinstance(n, ast.Call):
            f = getattr(n.func, "attr", None)
            if f == "update":
                for k in n.keywords:
                    if k.arg in flags and _const(k.value) is False:
                        out.append(_cookie_finding(k.arg, rel, n.lineno, flags))
            continue
        if key in flags and val is not None and _const(val) is False:
            out.append(_cookie_finding(key, rel, n.lineno, flags))
    return [f for f in out if f]


def _cookie_finding(key, rel, line, flags):
    why = flags.get(key)
    if why is None:
        return None
    return {"tool": "gotcha", "rule": "cookie/insecure-session-flag",
            "file": rel, "line": line, "sev": "MEDIUM",
            "message": f"`{key}` is disabled, so the session cookie is {why}",
            "remedy": (f"leave `{key}` at its secure default; if a development stack needs it "
                       f"off, set it there rather than in the shipped configuration")}


LANES = (_cors, _cookies)


def scan_tree(root):
    """Policy-free findings over a tree. Returns (findings, unparsed_or_None)."""
    root = os.path.abspath(root)
    out = []
    for path in _py_files(root):
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None, rel                     # unreadable is not clean
        found = []
        for lane in LANES:
            found += lane(tree, rel)
        if _dev_only(rel):
            for f in found:
                f["advisory"] = True
                f["sev"] = "INFO"
                f["message"] += (" (this file describes a development or test setup, so it "
                                 "is reported for review rather than counted)")
        out += found
    return out, None


POS = '''from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = False
CORS(app, origins="*", supports_credentials=True)
'''
NEG = '''from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
# A wildcard WITHOUT credentials is a public API, not a defect.
CORS(app, origins="*")
# Credentials WITH a named origin is the correct pairing.
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
'''


def _selftest():
    import tempfile
    ok = True
    for label, src, expect in (("positive", POS, True), ("negative", NEG, False)):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.py"), "w").write(src)
            f, _ = scan_tree(d)
            hit = bool(f)
            ok &= hit == expect
            print(f"[{'PASS' if hit == expect else 'FAIL'}] {label}: {len(f)} finding(s), "
                  f"expected {'>=1' if expect else '0'}")
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "tests"))
        open(os.path.join(d, "tests", "app.py"), "w").write(POS)
        f, _ = scan_tree(d)
        adv = bool(f) and all(x.get("advisory") for x in f)
        ok &= adv
        print(f"[{'PASS' if adv else 'FAIL'}] dev-context: {len(f)} finding(s), all advisory")
    print("all gotcha-lane controls passed" if ok else "CONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    f, bad = scan_tree(args[0] if args else ".")
    if bad:
        print(f"UNMEASURED: {bad} does not parse")
        sys.exit(2)
    gated = [x for x in f if not x.get("advisory")]
    print(f"{len(gated)} gated, {len(f) - len(gated)} advisory")
    for x in f:
        print(f"  [{x['sev']:6s}] {x['rule']:34s} {x['file']}:{x['line']}")
        print(f"           {x['message']}")
