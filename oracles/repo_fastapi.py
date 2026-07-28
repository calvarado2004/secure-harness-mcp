#!/usr/bin/env python3
"""FastAPI-specific security lane: defects that live in how the framework BINDS parameters.

WHY THIS LANE EXISTS
An external agent scanning this repository through the harness reported a defect no lane
here could see, and it is one line:

    @router.post("/login")
    def login(username: str, password: str, db: Session = Depends(get_db)):

In FastAPI a scalar-annotated parameter that is not a path parameter and carries no
explicit Body/Form/Header/Cookie marker is a QUERY parameter. So the password travels in
the URL: browser history, the Referer header on any outbound link, nginx access logs, proxy
logs, and every monitoring pipeline downstream of them. Nothing in the repository looks
wrong -- there is no string concatenation, no missing check, no dangerous call. bandit sees
nothing because there is nothing to pattern-match; the authorization lane sees an endpoint
that is deliberately public; a dataflow engine sees a value that never reaches a sink.

The defect is in the BINDING, which is framework semantics. That is precisely the class the
project's authorization lane already argues for: generic engines cannot answer questions
whose answer lives in a framework's conventions, and a forty-line AST pass over those
conventions finds what they structurally cannot.

WHAT IT DELIBERATELY DOES NOT DO
It does not track where the value goes. It reports that a credential-named value is bound
to the query string, which is a defect at the moment of binding regardless of what happens
next.
"""
import ast
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_authz import (SKIP_DIRS, _handlers, _router_prefix,  # noqa: E402
                        _py_files)

# Parameter names whose appearance in a URL is a defect. Credentials and the identifiers
# they are paired with -- a username in a log is a smaller problem than a password, and it
# is still an identifier nobody meant to publish.
CREDENTIAL_NAMES = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "otp", "mfa_code", "credential", "auth",
    "username", "user", "email", "login",
}

# Markers that bind a parameter somewhere OTHER than the query string. If any of these is
# the parameter's default, the value is not in the URL and this lane must stay silent.
NON_QUERY_MARKERS = {"Body", "Form", "File", "UploadFile", "Header", "Cookie", "Depends",
                     "Security", "Path"}

# Annotations that FastAPI treats as scalars, i.e. query parameters. A Pydantic model is a
# request body and is the correct way to accept credentials.
SCALAR_ANNOTATIONS = {"str", "int", "float", "bool", "bytes", "UUID", "date", "datetime"}

# Documentation surfaces FastAPI publishes unless told otherwise.
INTROSPECTION_ROUTES = {"/docs", "/redoc", "/openapi.json"}


def _marker(default):
    """The binding marker in a parameter default, e.g. `Depends(...)` -> 'Depends'."""
    if isinstance(default, ast.Call):
        fn = default.func
        return getattr(fn, "id", None) or getattr(fn, "attr", None)
    return getattr(default, "id", None) or getattr(default, "attr", None)


def _annotation_name(node):
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):          # Optional[str], Annotated[str, ...]
        return _annotation_name(node.slice)
    if isinstance(node, ast.Tuple) and node.elts:
        return _annotation_name(node.elts[0])
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _path_params(route):
    """Names inside {braces} in the route template: these are path, not query."""
    out, depth, cur = set(), 0, ""
    for ch in route:
        if ch == "{":
            depth, cur = depth + 1, ""
        elif ch == "}" and depth:
            depth -= 1
            out.add(cur.split(":")[0])
        elif depth:
            cur += ch
    return out


def _query_params(func, route):
    """Parameters FastAPI will bind from the query string."""
    args = func.args
    pos = list(args.args) + list(args.kwonlyargs)
    defaults = ([None] * (len(args.args) - len(args.defaults)) + list(args.defaults)
                + list(args.kw_defaults))
    in_path = _path_params(route)
    out = []
    for arg, default in zip(pos, defaults):
        if arg.arg in ("self", "cls") or arg.arg in in_path:
            continue
        if _marker(default) in NON_QUERY_MARKERS:
            continue
        ann = _annotation_name(arg.annotation)
        # An un-annotated parameter is also a query parameter, but reporting those would
        # fire on ordinary code; the credential check below is what makes this precise.
        if ann is not None and ann not in SCALAR_ANNOTATIONS:
            continue                              # a model: this is a request body
        out.append(arg)
    return out


def _has_docs_disabled(tree):
    """Was FastAPI() constructed with docs_url=None / openapi_url=None?"""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (getattr(node.func, "id", None)
                                           or getattr(node.func, "attr", None)) == "FastAPI":
            off = {kw.arg for kw in node.keywords
                   if isinstance(kw.value, ast.Constant) and kw.value.value is None}
            if {"docs_url", "openapi_url"} & off:
                return True
    return False


def scan_fastapi(root, public_routes=None):
    """Findings for a FastAPI tree. Returns (findings, unparseable_file_or_None).

    `public_routes` is the project's declared public surface. It is optional: the
    credential rule does not need it, and the introspection rule is skipped without it
    rather than guessed at, because "is this route meant to be public" is exactly the
    question only the project can answer.
    """
    root = os.path.abspath(root)
    findings, saw_app = [], False
    for path in _py_files(root):
        rel = os.path.relpath(path, root)
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None, rel          # unparseable: no answer, not "no findings"

        prefix = _router_prefix(tree)
        for method, route, func, dec in _handlers(tree):
            full = (prefix + route) or "/"
            for arg in _query_params(func, route):
                if arg.arg.lower() not in CREDENTIAL_NAMES:
                    continue
                findings.append({
                    "tool": "fastapi", "rule": "py/credential-in-query", "file": rel,
                    "line": func.lineno, "sev": "HIGH",
                    "message": (f"{method} {full}: `{arg.arg}` is a scalar parameter with "
                                f"no Body/Form/Header binding, so FastAPI reads it from "
                                f"the QUERY STRING -- the credential travels in the URL"),
                    "remedy": ("accept credentials in a request body: declare a Pydantic "
                               "model parameter, or use `Form(...)` for a form post (which "
                               "is what OAuth2PasswordRequestForm does). Never let a "
                               "credential be a query parameter."),
                })

        # Framework-published documentation, if the project did not declare it public.
        if public_routes is not None:
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and (getattr(node.func, "id", None)
                             or getattr(node.func, "attr", None)) == "FastAPI"):
                    saw_app = True
                    if _has_docs_disabled(tree):
                        continue
                    undeclared = sorted(INTROSPECTION_ROUTES - set(public_routes))
                    if undeclared:
                        findings.append({
                            "tool": "fastapi", "rule": "py/undeclared-api-introspection",
                            "file": rel, "line": node.lineno, "sev": "MEDIUM",
                            "message": (f"FastAPI publishes {', '.join(undeclared)} by "
                                        f"default and the project does not declare them "
                                        f"public; the full API map is served to anyone "
                                        f"who can reach the app"),
                            "remedy": ("either declare these routes public in the project "
                                       "profile -- making it a decision someone signed -- "
                                       "or pass docs_url=None and openapi_url=None outside "
                                       "development"),
                        })
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings, None


# ---------------------------------------------------------------------------
POS_LOGIN = '''
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/auth")


@router.post("/login")
def login(username: str, password: str, db=Depends(get_db)):
    """Both credentials are scalar, unmarked and not in the path: query parameters."""
    return {"token": issue(username, password)}
'''

NEG_LOGIN = '''
from fastapi import APIRouter, Depends, Form
from pydantic import BaseModel
router = APIRouter(prefix="/auth")


class Credentials(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(payload: Credentials, db=Depends(get_db)):
    """A model parameter is a request BODY. Silence is correct."""
    return {"token": issue(payload.username, payload.password)}


@router.post("/token")
def token(username: str = Form(...), password: str = Form(...)):
    """Form(...) is a form body, not the query string. Silence is correct."""
    return {"token": issue(username, password)}


@router.get("/users/{username}")
def profile(username: str):
    """A PATH parameter. It is in the URL by design and is not a credential binding."""
    return {"user": username}


@router.get("/search")
def search(q: str, limit: int = 20):
    """Ordinary query parameters that are not credentials. Silence is correct."""
    return {"q": q, "limit": limit}
'''


def _selftest():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        pos, neg = os.path.join(td, "pos"), os.path.join(td, "neg")
        os.makedirs(pos)
        os.makedirs(neg)
        open(os.path.join(pos, "auth.py"), "w").write(POS_LOGIN)
        open(os.path.join(neg, "auth.py"), "w").write(NEG_LOGIN)

        pf, _ = scan_fastapi(pos)
        hit = any(f["rule"] == "py/credential-in-query" for f in pf)
        print(("[PASS] " if hit else "[FAIL] ")
              + "positive control: a scalar `password` parameter is reported")
        ok = ok and hit
        n = len([f for f in pf if f["rule"] == "py/credential-in-query"])
        two = n == 2
        print(("[PASS] " if two else "[FAIL] ")
              + f"positive control: both credentials reported (got {n}, want 2)")
        ok = ok and two

        nf, _ = scan_fastapi(neg)
        got = {f["rule"] for f in nf}
        for label in ["a Pydantic model parameter is a request body",
                      "Form(...) is a form body, not the query string",
                      "a path parameter is not a credential binding",
                      "ordinary non-credential query parameters are not findings"]:
            clean = "py/credential-in-query" not in got
            print(("[PASS] " if clean else "[FAIL] ") + f"negative control: {label}")
            ok = ok and clean

        # unmeasurable
        bad = os.path.join(td, "bad")
        os.makedirs(bad)
        open(os.path.join(bad, "broken.py"), "w").write("def f(:\n")
        f, where = scan_fastapi(bad)
        unm = f is None and where is not None
        print(("[PASS] " if unm else "[FAIL] ")
              + "a file that does not parse returns UNMEASURED, not zero findings")
        ok = ok and unm

        # the introspection rule needs the project's declared surface
        pf2, _ = scan_fastapi(pos, public_routes={"/auth/login"})
        print("[PASS] introspection rule is skipped when no FastAPI() app is constructed"
              if not any(f["rule"] == "py/undeclared-api-introspection" for f in pf2)
              else "[FAIL] introspection rule fired without an app")
    print("\nall fastapi-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    found, bad = scan_fastapi(sys.argv[1],
                              public_routes=set(sys.argv[2].split(",")) if len(sys.argv) > 2
                              else None)
    if found is None:
        print(f"UNMEASURED: {bad} does not parse")
        sys.exit(2)
    print(json.dumps(found, indent=2))
    for f in found:
        print(f"  [{f['sev']:<6}] {f['rule']:<32} {f['file']}:{f['line']} — {f['message']}")
