#!/usr/bin/env python3
"""An authorization lane: the defects a generic analyzer structurally cannot report.

WHY THIS EXISTS
Run the commodity engines over this repository and you get one finding (a false positive
on the string "bearer") from bandit and zero from semgrep -- while the application serves
its entire customer table to anonymous callers and lets anyone register as an
administrator. That is not a failure of those tools. "Is this endpoint authorized?" has no
general answer: it depends on who is supposed to be able to do what, which lives in the
project's head, not in its syntax.

It becomes answerable the moment you are willing to write down two things about YOUR
stack:

    AUTH_DEPS       which dependencies establish identity in this framework
    SENSITIVE       which resources are not public in this application

For FastAPI, "is this route authenticated" is then just a question about the handler's
dependency list, which is forty lines of AST away. That is the whole argument for
customising a harness: the generic lanes are commodity and nearly worthless here; the
project-specific lane is cheap and finds everything that matters.

WHAT IT DELIBERATELY DOES NOT DO
It does not prove exploitability -- the behavioural battery does that. It does not model
role hierarchies or object-level ownership. It answers four structural questions whose
"no" is nearly always a real defect, and it says so rather than implying more.
"""
import ast
import json
import os
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}

# ---- the two facts a practitioner supplies about their own project ----------
AUTH_DEPS = {"get_current_user", "get_current_active_user", "require_user",
             "require_admin", "get_admin_user", "verify_token"}
# Routes that are anonymous ON PURPOSE. A lane that cannot be told this flags the login
# endpoint for not requiring a login, and the practitioner learns to ignore it -- which is
# how a rule set dies. Declaring public surface explicitly is the point: it turns an
# omission into a decision someone signed.
PUBLIC_ROUTES = {"/auth/login", "/auth/register", "/auth/token", "/health", "/"}
SENSITIVE = {"Customer", "Employee", "Sale", "User", "Appointment"}
PRIV_FIELDS = {"role", "is_admin", "is_superuser", "is_staff", "is_active", "permissions",
               "scopes"}
ROLE_HINTS = ("role", "permission", "scope", "is_admin", "is_superuser", "forbidden",
              "403")
SECRETISH = ("secret", "password", "token", "api_key", "apikey", "private_key")
# Credentials for the services in the project's OWN dev stack. A compose file ships with
# working local values by design, and the deployment overrides them from the environment;
# flagging those at HIGH buries the one default that actually matters under noise the
# practitioner is right to ignore. They stay visible at LOW rather than being suppressed --
# this is a pricing decision, not a blind spot.
LOCAL_STACK_CREDS = {"postgres_password", "postgres_user", "minio_access_key",
                     "minio_secret_key", "minio_root_password"}
# Fields whose client-settability is outright privilege escalation, versus merely wrong.
HARD_PRIV = {"role", "is_admin", "is_superuser", "is_staff", "permissions", "scopes"}

METHODS = {"get", "post", "put", "delete", "patch"}
WRITE = {"POST", "PUT", "DELETE", "PATCH"}


def _py_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def _depends_names(node):
    """Every NAME inside a `Depends(NAME)` default in this handler's signature."""
    names = []
    for d in list(node.args.defaults) + list(node.args.kw_defaults):
        if not isinstance(d, ast.Call):
            continue
        fn = d.func
        if (getattr(fn, "id", None) or getattr(fn, "attr", None)) != "Depends":
            continue
        for a in d.args:
            n = getattr(a, "id", None) or getattr(a, "attr", None)
            if n:
                names.append(n)
    return names


def _router_prefix(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            if (getattr(fn, "id", None) or getattr(fn, "attr", None)) in ("APIRouter",
                                                                         "FastAPI"):
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        return kw.value.value
    return ""


def _handlers(tree):
    """(method, path, funcdef, decorator_call) for each route handler."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            fn = dec.func
            if not isinstance(fn, ast.Attribute) or fn.attr not in METHODS:
                continue
            path = dec.args[0].value if (dec.args and isinstance(dec.args[0],
                                                                ast.Constant)) else ""
            out.append((fn.attr.upper(), path, node, dec))
    return out


def _touches_sensitive(func, dec):
    """Does this handler read or return a resource the project called sensitive?"""
    for kw in dec.keywords:
        if kw.arg == "response_model":
            if any(n in ast.dump(kw.value) for n in SENSITIVE):
                return True
    body = ast.dump(func)
    return any(f"id='{n}'" in body for n in SENSITIVE)


def _auth_params(node):
    """Parameter names bound to an identity dependency."""
    names, args = [], node.args
    pos = list(args.args) + list(args.kwonlyargs)
    defaults = ([None] * (len(args.args) - len(args.defaults)) + list(args.defaults)
                + list(args.kw_defaults))
    for arg, d in zip(pos, defaults):
        if not isinstance(d, ast.Call):
            continue
        fn = d.func
        if (getattr(fn, "id", None) or getattr(fn, "attr", None)) != "Depends":
            continue
        for a in d.args:
            if (getattr(a, "id", None) or getattr(a, "attr", None)) in AUTH_DEPS:
                names.append(arg.arg)
    return names


def _has_role_check(func):
    """Does the handler make any decision about WHO the caller is?

    Two ways to qualify. Either it mentions a role/permission/403, or it actually USES the
    authenticated principal in its body -- binding the identity to `current_user` and
    scoping the query by it is ownership authorization, and flagging that would be wrong.
    The tell for the real defect is the opposite: `_: User = Depends(get_current_user)`,
    which discards the principal and asserts only "somebody is logged in".
    """
    src = ast.dump(func).lower()
    if any(h in src for h in ROLE_HINTS):
        return True
    used = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
    return any(p in used for p in _auth_params(func) if not p.startswith("_"))


def scan_authz(root):
    root = os.path.abspath(root)
    findings = []
    for path in _py_files(root):
        rel = os.path.relpath(path, root)
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None, rel            # unparseable: no answer, not "no findings"

        # ---- 1 & 2: route-level authentication and authorization -------------
        prefix = _router_prefix(tree)
        for method, route, func, dec in _handlers(tree):
            full = (prefix + route) or "/"
            if not _touches_sensitive(func, dec) or full in PUBLIC_ROUTES:
                continue
            authed = bool(set(_depends_names(func)) & AUTH_DEPS)
            if not authed:
                findings.append({
                    "tool": "authz", "rule": "authz/unauthenticated-data-access",
                    "file": rel, "line": func.lineno, "sev": "HIGH",
                    "message": f"{method} {full} exposes a sensitive resource with no "
                               f"authentication dependency",
                    "remedy": "add the project's identity dependency to this handler "
                              "(e.g. `user: User = Depends(get_current_user)`); if the "
                              "endpoint is genuinely public, say so explicitly rather "
                              "than by omission",
                })
            elif method in WRITE and not _has_role_check(func):
                findings.append({
                    "tool": "authz", "rule": "authz/authenticated-but-unauthorized",
                    "file": rel, "line": func.lineno, "sev": "MEDIUM",
                    "message": f"{method} {full} checks that the caller is logged in but "
                               f"never checks WHAT they are allowed to do",
                    "remedy": "authorize on the caller's role or on ownership of the "
                              "object being modified, and return 403 when it fails; "
                              "authentication is not authorization",
                })

        # ---- 3: privilege fields a client can set --------------------------
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {getattr(b, "id", None) or getattr(b, "attr", None)
                     for b in node.bases}
            if "BaseModel" not in bases:
                continue
            inbound = any(k in node.name.lower() for k in ("create", "update", "in",
                                                           "register", "request"))
            if not inbound:
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    if stmt.target.id in PRIV_FIELDS:
                        findings.append({
                            "tool": "authz", "rule": "authz/client-settable-privilege",
                            "file": rel, "line": stmt.lineno,
                            "sev": "HIGH" if stmt.target.id in HARD_PRIV else "MEDIUM",
                            "message": f"`{node.name}.{stmt.target.id}` is supplied by the "
                                       f"client, so a caller can choose their own privilege",
                            "remedy": "remove the field from the inbound schema and set it "
                                      "server-side; privilege must never be a request "
                                      "parameter",
                        })

        # ---- 4: shipped default credentials --------------------------------
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name, val = node.target.id.lower(), node.value
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                    isinstance(node.targets[0], ast.Name):
                name, val = node.targets[0].id.lower(), node.value
            else:
                continue
            if not any(s in name for s in SECRETISH):
                continue
            if isinstance(val, ast.Constant) and isinstance(val.value, str) \
                    and len(val.value) >= 4:
                local = name in LOCAL_STACK_CREDS
                findings.append({
                    "tool": "authz", "rule": "authz/shipped-default-credential",
                    "file": rel, "line": node.lineno,
                    "sev": "LOW" if local else "HIGH",
                    "message": (f"`{name}` is a local-stack service credential with a dev "
                                f"default (expected; overridden by the deployment)"
                                if local else
                                f"`{name}` has a working default baked into the source, so "
                                f"a deployment that forgets to override it is secured with "
                                f"a value everyone can read"),
                    "remedy": ("confirm the deployment overrides this from the environment"
                               if local else
                               "require the value from the environment and refuse to start "
                               "when it is absent, rather than falling back to a literal"),
                })
    return findings, None


# ---------------------------------------------------------------------------
NEG = '''
from pydantic import BaseModel
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/auth")

class CustomerCreate(BaseModel):
    first_name: str
    email: str

@router.get("/", response_model=list[CustomerResponse])
def list_customers(db=Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Customer).all()

@router.delete("/{cid}")
def delete_customer(cid: int, db=Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403)
    db.delete(db.query(Customer).get(cid))

@router.post("/login")
def login(db=Depends(get_db)):
    return db.query(User).first()

@router.post("/mine")
def create_mine(db=Depends(get_db), current_user: User = Depends(get_current_user)):
    a = Appointment(customer_id=current_user.id)
    db.add(a)
'''


def _selftest():
    import tempfile
    ok = True
    here = os.path.dirname(os.path.abspath(__file__))
    base = os.path.join(os.path.dirname(here), "car_dealership_original_code")
    findings, bad = scan_authz(base)
    got = {f["rule"] for f in findings}
    for rule in ["authz/unauthenticated-data-access", "authz/client-settable-privilege",
                 "authz/shipped-default-credential"]:
        hit = rule in got
        print(("[PASS] " if hit else "[FAIL] ") + f"positive control (real repo): {rule}")
        ok = ok and hit
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "r.py"), "w").write(NEG)
        nf, _ = scan_authz(td)
        ngot = {f["rule"] for f in nf}
        for label, rule in [("an authenticated listing is not flagged",
                             "authz/unauthenticated-data-access"),
                            ("a declared-public route is not flagged",
                             "authz/unauthenticated-data-access"),
                            ("using the principal for ownership counts as authorization",
                             "authz/authenticated-but-unauthorized"),
                            ("a role-checked delete is not flagged",
                             "authz/authenticated-but-unauthorized"),
                            ("a schema without privilege fields is not flagged",
                             "authz/client-settable-privilege")]:
            clean = rule not in ngot
            print(("[PASS] " if clean else "[FAIL] ") + f"negative control: {label}")
            ok = ok and clean
    print("\nall authorization-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    fs, bad = scan_authz(sys.argv[1])
    if bad:
        print(f"unparseable: {bad}")
        sys.exit(2)
    print(f"{len(fs)} authorization findings")
    for f in fs:
        print(f"  [{f['sev']:6s}] {f['rule']:38s} {f['file']}:{f['line']}\n"
              f"           {f['message']}")
