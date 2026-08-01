#!/usr/bin/env python3
"""An authorization lane for Express, which is the third framework to need the same rules.

WHY THIS EXISTS
The authorization rules were written against FastAPI, where identity is a dependency in the
handler's signature, and then bound for Flask, where it is a decorator or a read of
`session`. Express spells it a third way: middleware positioned in the route's argument list,
before the handler. To the other two lanes an Express route looks like a function nobody
guards, which is how a product with sixty-eight well-written backend files ends up reported
as sixty-eight files nobody can read.

So this binds the same rule ids again. `authz/unauthenticated-data-access` means the same
thing and carries the same weight whether the missing guard is a FastAPI dependency, a Flask
decorator or an Express middleware. Only the reading is framework-specific.

THE DISTINCTION THIS FRAMEWORK FORCED
Express projects commonly ship two identity middlewares: one that REQUIRES a caller and
answers 401 without one, and one that attaches the caller if a token happens to be present
and continues regardless. They look identical in a route chain and they are opposites. A
lane that treats both as authentication will pass an endpoint that serves private data to
anonymous callers, so the two are declared separately, `auth_middleware` and
`optional_auth_middleware`, and only the first counts as a guard.

WHAT IT READS, AND HOW HONESTLY
There is no TypeScript parser here. This is a brace-matching scanner over source text, which
is enough to find a route's argument list, its middleware and its handler body, and is not
enough to follow a chain assembled at runtime or a router built by a helper. LIMITS.md says
so. A lane that cannot read a construct must report the file as unread rather than clean,
and `scan_express_authz` returns its unreadable set for exactly that reason.
"""
import os
import re
import sys

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv"}

# ---- the facts a practitioner supplies about their own project --------------
# Middleware that REQUIRES an authenticated caller.
AUTH_MIDDLEWARE = {"authenticate", "requireAuth", "requireUser", "isAuthenticated",
                   "ensureAuthenticated", "protect", "authGuard", "verifyToken",
                   "requireLogin", "jwtRequired"}
# Middleware that attaches a caller IF ONE IS PRESENT and continues either way. NOT a guard.
OPTIONAL_AUTH_MIDDLEWARE = {"optionalAuth", "maybeAuth", "softAuth", "attachUser"}
# PROJECT INTENT HAS THREE STATES, as everywhere else in this harness. A route the project
# declared public is silent; one it declared sensitive is a gated finding when unguarded; one
# it declared NOTHING about is an advisory, reported and never gated. The third state is what
# a public user profile is: this application serves one deliberately, through a projection
# that selects a username, an avatar and a rating, and it never wrote that intention down.
# Gating on it would tell a correct product to break itself.
PUBLIC_ROUTES = {"/health", "/api/auth/register", "/api/auth/login", "/api/auth/refresh",
                 "/api/theory/categories", "/api/theory/lessons"}
SENSITIVE_ROUTES = {"/api/auth/logout", "/api/theory/progress"}
SENSITIVE_PREFIXES = ("/api/users/me", "/api/theory/progress")
# Resources that are not public in this application. Matched on WORD boundaries: substring
# matching read "middlegame" as "game" and reported a hardcoded list of four lesson labels
# as an unguarded leak of game data.
SENSITIVE = {"user", "users", "profile", "account", "game", "games", "history", "elo",
             "progress", "session", "token", "password", "email"}
_SENSITIVE_RE = re.compile(r"\b(" + "|".join(sorted(SENSITIVE)) + r")\b", re.I)
PRIV_FIELDS = {"role", "isAdmin", "is_admin", "isSuperuser", "permissions", "scopes",
               "isStaff"}
# Terms that mark an expression as an identity or ownership use.
PRINCIPAL = ("req.userId", "req.username", "req.user", "currentUser", "authReq.userId",
             "res.locals.user")
DENY = ("403", "401", "forbidden", "unauthorized", "not allowed", "insufficient")

METHODS = ("get", "post", "put", "delete", "patch")
WRITE = {"POST", "PUT", "DELETE", "PATCH"}

_ROUTE = re.compile(r"\b(router|app)\.(" + "|".join(METHODS) + r")\s*\(", re.I)
_MOUNT = re.compile(r"\b(?:app|router)\.use\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)")
_IMPORT = re.compile(r"import\s+(\w+)\s+from\s+['\"]\.\/routes\/([\w.-]+?)(?:\.js)?['\"]")


def _files(root, exts=(".ts", ".js"), skip_tests=True):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(exts) or fn.endswith(".d.ts"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            if skip_tests and re.search(r"(^|/)(tests?|__tests__)/|\.(test|spec)\.", rel):
                continue
            out.append(rel)
    return out


def _balanced(src, open_idx, opener="(", closer=")"):
    """Text between `open_idx` (at an opener) and its match, skipping strings."""
    depth, i, n = 0, open_idx, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return src[open_idx + 1:i], i
        i += 1
    return None, None


def _mount_prefixes(root, files):
    """routes/<name> -> the path it is mounted under, read from the app's own wiring."""
    ident_to_file, prefixes = {}, {}
    for rel in files:
        try:
            src = open(os.path.join(root, rel), encoding="utf8", errors="replace").read()
        except OSError:
            continue
        for ident, name in _IMPORT.findall(src):
            ident_to_file[ident] = name
        for prefix, ident in _MOUNT.findall(src):
            prefixes[ident] = prefix
    return {ident_to_file[i]: p for i, p in prefixes.items() if i in ident_to_file}


def _routes_in(src):
    """(method, path, middleware_names, handler_body, line) for each route in one file."""
    out = []
    for m in _ROUTE.finditer(src):
        args, end = _balanced(src, m.end() - 1)
        if args is None:
            continue
        line = src.count("\n", 0, m.start()) + 1
        pm = re.match(r"\s*['\"]([^'\"]*)['\"]", args)
        path = pm.group(1) if pm else ""
        rest = args[pm.end():] if pm else args
        # Middleware are the bare identifiers and calls that precede the handler; the
        # handler is the first arrow or `function` in the list.
        h = re.search(r"(async\s*)?\(|\bfunction\b", rest)
        head = rest[:h.start()] if h else rest
        mw = set(re.findall(r"\b([A-Za-z_]\w*)\s*(?:\(|,|$)", head))
        body = rest[h.start():] if h else ""
        out.append((m.group(2).upper(), path, mw, body, line))
    return out


def _touches_sensitive(path, body):
    return bool(_SENSITIVE_RE.search(path + " " + body))


def _intent(full):
    """What the project has said about this route: public, sensitive, or nothing."""
    if full in PUBLIC_ROUTES:
        return "public"
    if full in SENSITIVE_ROUTES or full.startswith(SENSITIVE_PREFIXES):
        return "sensitive"
    return "undeclared"


def _uses_principal(body):
    return any(p.lower() in body.lower() for p in PRINCIPAL)


def _makes_decision(body, mw):
    low = body.lower()
    if any(p.lower() in low for p in PRIV_FIELDS):
        return True
    if any(d in low for d in DENY):
        return True
    return _uses_principal(body)


def scan_express_authz(root):
    """Authorization findings in Express code. Returns (findings, unreadable_or_None)."""
    root = os.path.abspath(root)
    files = _files(root)
    prefixes = _mount_prefixes(root, files)
    findings = []
    for rel in files:
        try:
            src = open(os.path.join(root, rel), encoding="utf8", errors="replace").read()
        except OSError:
            return None, rel
        stem = os.path.splitext(os.path.basename(rel))[0]
        prefix = prefixes.get(stem, "")
        for method, path, mw, body, line in _routes_in(src):
            full = (prefix + path).replace("//", "/").rstrip("/") or "/"
            if not _touches_sensitive(full, body):
                continue
            intent = _intent(full)
            if intent == "public":
                continue
            undeclared = intent == "undeclared"
            guarded = bool(mw & AUTH_MIDDLEWARE)
            optional_only = bool(mw & OPTIONAL_AUTH_MIDDLEWARE) and not guarded

            if not guarded:
                findings.append({
                    "tool": "authz", "rule": "authz/unauthenticated-data-access",
                    "file": rel, "line": line,
                    "sev": "INFO" if undeclared else "HIGH", "advisory": undeclared,
                    "message": (
                        f"{method} {full} serves a resource the project declared non-public "
                        + ("behind middleware that attaches a caller only when one is "
                           "present and continues either way, so an anonymous request "
                           "reaches the handler"
                           if optional_only else
                           "and no middleware in its chain requires an authenticated "
                           "caller")),
                    "remedy": ("put the project's requiring identity middleware in this "
                               "route's chain. Middleware that attaches a caller when a "
                               "token happens to be present does not refuse one without a "
                               "token, and is not a guard; if the endpoint is genuinely "
                               "public, declare it so rather than leaving it open by "
                               "omission"),
                })
            elif method in WRITE and not _makes_decision(body, mw):
                findings.append({
                    "tool": "authz", "rule": "authz/authenticated-but-unauthorized",
                    "file": rel, "line": line,
                    "sev": "INFO" if undeclared else "MEDIUM", "advisory": undeclared,
                    "message": f"{method} {full} requires a caller but never uses or checks "
                               f"who they are",
                    "remedy": "authorize on the caller's role or on ownership of the object "
                              "being modified, and answer 403 when it fails; authentication "
                              "is not authorization",
                })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings, None


if __name__ == "__main__":
    fs, bad = scan_express_authz(sys.argv[1])
    if bad:
        print(f"unreadable: {bad}")
        sys.exit(2)
    print(f"{len(fs)} authorization finding(s)")
    for f in fs:
        print(f"  [{f['sev']:6s}] {f['rule']:38s} {f['file']}:{f['line']}\n"
              f"           {f['message']}")
