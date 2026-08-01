#!/usr/bin/env python3
"""An authorization lane for Flask: the same four questions, a different framework.

WHY THIS EXISTS
The authorization rules were written against FastAPI, where "is this route authenticated"
is a question about the handler's dependency list. Study 1's applications are single-file
Flask services, and the same defects there are invisible to that lane for a reason that has
nothing to do with authorization: Flask spells identity as a decorator or as a read of
`session`/`g`/a header, not as `Depends(...)`. One of Study 1's shipped services surrenders
another user's private note through `/export` while scoring zero on both static batteries,
and the reason no lane named it is that no lane could read the framework it was written in.

So this binds the existing rule ids rather than declaring new ones. `authz/
unauthenticated-data-access` means the same thing, carries the same weight and is counted
once, whether the handler that lacks a guard is a FastAPI route or a Flask one. A repository
using both frameworks scores one defect per defect, not one per framework.

THE ONE NEW RULE, AND WHY IT IS NEW
`authz/decision-without-denial` is not "no authorization". It is worse and it is commoner:
the handler reads the caller's identity, compares it against the object's owner, and then
does nothing with the answer. Study 1's surviving IDOR is exactly this. The comparison is
present, so every rule that asks "does this handler check?" answers yes; the branch that
should deny is simply missing, so the check changes nothing about what the handler returns.
It is declared in packs/general/security because the defect is framework-independent, and
bound here because reading it is not.

WHAT IT DELIBERATELY DOES NOT DO
It does not prove exploitability; the behavioural battery does that. It does not model role
hierarchies or object ownership beyond the structural question of whether a decision is
acted on. It answers questions whose "no" is nearly always a real defect, and says so
rather than implying more.
"""
import ast
import os
import re
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}

# ---- the facts a practitioner supplies about their own project --------------
# Decorators that establish identity in this application. Names are matched exactly, and
# then by token, because the same guard is spelled `@require_auth`, `@login_required` and
# `@require_role("admin")` across the corpus, and the last is a decorator FACTORY whose call
# wrapper hides the name from an exact match. A lane that reads only the spellings one
# project happens to use reports every other project as unauthenticated.
AUTH_DECORATORS = {"login_required", "require_auth", "auth_required", "token_required",
                   "requires_auth", "jwt_required", "admin_required", "require_admin",
                   "requires_login", "require_role", "requires_role", "roles_required",
                   "role_required", "permission_required", "requires_permission",
                   "require_permission", "authenticated", "protected"}
AUTH_DECORATOR_TOKENS = ("auth", "login", "token", "role", "permission", "admin", "jwt")
# Expressions whose presence in a body means the handler read the caller's identity itself,
# which is how Flask code that carries no decorator still authenticates.
AUTH_READS = {"current_user", "get_current_user", "verify_token", "decode_token",
              "check_token", "authenticate", "get_user_from_token", "user_from_token"}
# Helper CALLS that establish identity. Matched by token after stripping leading
# underscores, because the same helper is `get_current_user` in one application and
# `_get_current_user` in the next, and an exact-name match reports the second as having no
# authentication at all. Deliberately excludes a bare "token": `secrets.token_urlsafe` is
# not an authentication check, and matching it would silence a genuinely open handler.
# The vocabulary is deliberately the SAME as the decorator one, minus a bare "token": a
# guard is a guard whether it is applied as `@require_admin` or called as
# `require_admin()` on the first line of the body, and the corpus uses both spellings for
# the same endpoint. `secrets.token_urlsafe` is why "token" is excluded here.
AUTH_CALL_TOKENS = ("current_user", "get_user", "user_from", "principal", "whoami",
                    "identify", "auth", "login", "role", "permission", "admin", "jwt")
AUTH_SOURCES = {"session", "g"}
AUTH_HEADERS = {"authorization", "x-api-token", "x-auth-token", "x-token", "api-key",
                "x-api-key"}
# PROJECT INTENT HAS THREE STATES, NOT TWO.
#
# A lane that knows only "public" and "sensitive" has to resolve everything else one way or
# the other, and both resolutions are wrong. Resolve undeclared to public and the lane has a
# blind spot it never reports. Resolve undeclared to sensitive and it reports conformant code
# as broken: on this corpus that is nineteen findings across twenty-five applications for
# behaviour the specification permits, and the repair loop then spends its round budget
# "fixing" endpoints that work. That is not hypothetical here; over-harnessing has already
# cost this project applications that shipped missing five specified routes.
#
# So the third state is named rather than resolved. It is the same discipline as the `m`
# coordinate elsewhere in this harness: "I could not measure this" must be distinct from "I
# found nothing", and "nobody declared this" must likewise be distinct from "this is fine"
# and from "this is a bug". An undeclared route produces an ADVISORY: reported to the model
# and to the reviewer, never counted toward the gated load, so it cannot drive repair and
# cannot break a working product. It is the observation an auditor writes when the finding
# is really a decision somebody has not made yet.
#
# Anonymous ON PURPOSE. Declaring public surface turns an omission into a signed decision.
PUBLIC_ROUTES = {"/", "/health", "/login", "/register", "/auth/login", "/auth/register",
                 "/static", "/favicon.ico", "/index"}
# Routes the specification ties to an authenticated or privileged caller. Unguarded here is
# a contradiction of a stated requirement, so it is a gated finding.
SENSITIVE_ROUTES = {"/notes", "/notes/import", "/admin/users", "/admin/backup"}
SENSITIVE_PREFIXES = ("/notes/", "/admin/")
# Everything else is UNDECLARED and produces an advisory, never a gated finding.
# Resources that are not public in this application.
SENSITIVE = {"note", "notes", "user", "users", "upload", "uploads", "file", "files",
             "export", "backup", "admin"}
PRIV_FIELDS = {"role", "is_admin", "is_superuser", "is_staff", "permissions", "scopes"}
# Terms that mark an expression as an identity or ownership comparison.
OWNERSHIP = ("owner", "user_id", "userid", "author", "created_by", "account_id",
             "current_user", "session", "token", "principal")
DENY = ("abort", "403", "401", "unauthorized", "forbidden", "access denied",
        "permission denied", "not allowed")

WRITE = {"POST", "PUT", "DELETE", "PATCH"}
METHODS = {"get", "post", "put", "delete", "patch", "route"}


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


def _decorator_names(func):
    """Every decorator name on this handler, however it is spelled."""
    out = set()
    for d in func.decorator_list:
        node = d.func if isinstance(d, ast.Call) else d
        n = getattr(node, "id", None) or getattr(node, "attr", None)
        if n:
            out.add(n)
    return out


def _handlers(tree):
    """(methods, path, funcdef) for every Flask route handler in this tree."""
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
            path = (dec.args[0].value
                    if dec.args and isinstance(dec.args[0], ast.Constant) else "")
            methods = {"GET"}
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = {e.value.upper() for e in kw.value.elts
                               if isinstance(e, ast.Constant)
                               and isinstance(e.value, str)}
            if fn.attr != "route":
                methods = {fn.attr.upper()}
            out.append((methods, path, node))
            break
    return out


def _intent(path):
    """What the project has said about this route: public, sensitive, or nothing."""
    base = path.split("<")[0].rstrip("/") or "/"
    if path in PUBLIC_ROUTES or base in PUBLIC_ROUTES:
        return "public"
    if path in SENSITIVE_ROUTES or base in SENSITIVE_ROUTES:
        return "sensitive"
    if any(base.startswith(p) for p in SENSITIVE_PREFIXES):
        return "sensitive"
    return "undeclared"


def _touches_sensitive(func, path):
    """Does this handler read or return a resource the project called sensitive?"""
    hay = (path + " " + ast.dump(func)).lower()
    return any(f"'{n}" in hay or f" {n}" in hay or f"/{n}" in hay for n in SENSITIVE)


def _guarded_by_decorator(func):
    names = _decorator_names(func)
    if names & AUTH_DECORATORS:
        return True
    return any(t in n.lower() for n in names for t in AUTH_DECORATOR_TOKENS)


def _route_params(path):
    """The names Flask binds from the URL, e.g. `/notes/<int:note_id>` -> {note_id}."""
    out = set()
    for seg in re.findall(r"<([^>]+)>", path or ""):
        out.add(seg.split(":")[-1].strip())
    return out


def _uses_injected_principal(func, path):
    """A guard decorator that hands the handler its caller, and a body that uses it.

    `@token_required def create_note(user)` passes the authenticated principal in as an
    argument, and the handler scopes the row by `user['username']`. That is ownership
    authorization, spelled as a parameter instead of as `g.user`. A lane that recognises only
    the framework's own globals reports this correct implementation as unauthorized, which is
    the harness charging a model for a defect it does not have.
    """
    if not _guarded_by_decorator(func):
        return False
    bound = _route_params(path)
    injected = [a.arg for a in list(func.args.args) + list(func.args.kwonlyargs)
                if a.arg not in bound and not a.arg.startswith("_")]
    if not injected:
        return False
    used = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
    return any(p in used for p in injected)


def _uses_principal(func):
    """Does the body reach for the authenticated caller at all?

    Binding the identity and scoping a query by it is ownership authorization, and flagging
    it would be wrong. The tell for the real defect is the opposite: a handler that carries
    an identity decorator and then never mentions the caller, so it asserts only that
    somebody is logged in.
    """
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id in AUTH_READS | AUTH_SOURCES:
            return True
        if isinstance(node, ast.Attribute):
            base = getattr(node.value, "id", None)
            if base in AUTH_SOURCES or node.attr in AUTH_READS:
                return True
        if isinstance(node, ast.Call):
            name = (getattr(node.func, "id", None)
                    or getattr(node.func, "attr", None) or "").lstrip("_").lower()
            if name and any(t in name for t in AUTH_CALL_TOKENS):
                return True
    return False


def _reads_identity(func):
    """Does the handler establish who the caller is, by decorator or by hand?"""
    if _guarded_by_decorator(func) or _uses_principal(func):
        return True
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.lower() in AUTH_HEADERS:
                return True
    return False


def _makes_decision(func):
    """Does the handler act on who the caller is, rather than only that they exist?"""
    src = ast.dump(func).lower()
    if any(p in src for p in PRIV_FIELDS) or any(d in src for d in DENY):
        return True
    # a decorator naming a role or a permission has already made the decision
    if any(t in n.lower() for n in _decorator_names(func)
           for t in ("role", "permission", "admin")):
        return True
    return _uses_principal(func)


def _body_is_inert(body):
    """A branch body that does nothing at all: `pass`, `...`, or a bare docstring."""
    stmts = [s for s in body
             if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                     and isinstance(s.value.value, str))]
    if not stmts:
        return True
    return all(isinstance(s, ast.Pass)
               or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                   and s.value.value is Ellipsis)
               for s in stmts)


def _decision_without_denial(func):
    """Conditionals that compute an authorization answer and then discard it.

    The shape is an `if` whose test names an identity or an owner, whose body does nothing,
    and which has no `else`. Control flow is therefore identical whether or not the caller
    owns the object, so the comparison is decoration. Requiring the body to be *inert*
    rather than merely non-returning is deliberate: a branch that assigns a variable is
    doing work this lane cannot follow, and reporting it would be a guess.
    """
    out = []
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        test = ast.dump(node.test).lower()
        if not any(t in test for t in OWNERSHIP):
            continue
        if not _body_is_inert(node.body):
            continue
        if node.orelse:                   # an else exists; it may well deny
            continue
        out.append(node)
    return out


def scan_flask_authz(root):
    """Authorization findings in Flask code. Returns (findings, unparsed_or_None)."""
    root = os.path.abspath(root)
    findings = []
    for path in _py_files(root):
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None, rel              # unparseable: no answer, not "no findings"

        for methods, route, func in _handlers(tree):
            full = route or "/"
            intent = _intent(full)
            if not _touches_sensitive(func, full) or intent == "public":
                continue
            verb = sorted(methods)[0]
            # An undeclared route is an unanswered question, not a defect. It is reported at
            # INFO and marked advisory, which keeps it out of the gated load.
            undeclared = intent == "undeclared"

            if not _reads_identity(func):
                findings.append({
                    "tool": "authz", "rule": "authz/unauthenticated-data-access",
                    "file": rel, "line": func.lineno,
                    "sev": "INFO" if undeclared else "HIGH", "advisory": undeclared,
                    "message": (f"{verb} {full} serves a resource to anonymous callers and "
                                f"the project has not declared whether it should. Decide: "
                                f"declare it public, or guard it"
                                if undeclared else
                                f"{verb} {full} exposes a resource the project declared "
                                f"non-public and never establishes who the caller is"),
                    "remedy": ("record the decision. If this endpoint is meant to be "
                               "anonymous, declare it public so the omission becomes a "
                               "signed choice; if it is not, apply the project's identity "
                               "guard to it"
                               if undeclared else
                               "apply the project's identity decorator to this handler, or "
                               "read and verify the caller's credential in it"),
                })
            elif methods & WRITE and not (_makes_decision(func)
                                          or _uses_injected_principal(func, full)):
                findings.append({
                    "tool": "authz", "rule": "authz/authenticated-but-unauthorized",
                    "file": rel, "line": func.lineno,
                    "sev": "INFO" if undeclared else "MEDIUM", "advisory": undeclared,
                    "message": f"{verb} {full} checks that the caller is logged in but "
                               f"never checks what they are allowed to do",
                    "remedy": "authorize on the caller's role or on ownership of the "
                              "object being modified, and return 403 when it fails; "
                              "authentication is not authorization",
                })

            for node in _decision_without_denial(func):
                findings.append({
                    "tool": "authz", "rule": "authz/decision-without-denial",
                    "file": rel, "line": node.lineno, "sev": "HIGH",
                    "message": f"{verb} {full} compares the caller against the object's "
                               f"owner and then proceeds either way: the branch that "
                               f"matches does nothing and there is no branch that denies",
                    "remedy": "make the comparison decide the response. Deny explicitly "
                              "on the failing path (return 403, or 404 so the endpoint "
                              "does not confirm the object exists) rather than falling "
                              "through to the success path",
                })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings, None


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    fs, bad = scan_flask_authz(sys.argv[1])
    if bad:
        print(f"unparseable: {bad}")
        sys.exit(2)
    print(f"{len(fs)} authorization findings")
    for f in fs:
        print(f"  [{f['sev']:6s}] {f['rule']:34s} {f['file']}:{f['line']}\n"
              f"           {f['message']}")
