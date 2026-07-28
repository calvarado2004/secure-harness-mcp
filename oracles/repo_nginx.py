#!/usr/bin/env python3
"""The edge lane: what the reverse proxy actually publishes.

WHY THIS LANE EXISTS
`nginx.conf` was, until this lane, the single file in the subject repository that no
runtime claimed and no blind-spot report mentioned. It decides what is reachable from
outside, which is the same question the authorization lane asks about handlers -- asked one
layer out, where the answer can silently disagree with the application's own intent.

It does disagree here. The project declares five public routes. The proxy publishes
`/docs` and `/openapi.json`, which are in neither the declared surface nor any handler
anyone wrote: FastAPI generates them, and the edge forwards them. Nobody made that
decision; it is the composition of two reasonable defaults, and the result is a complete
map of the API -- every path, every parameter, every schema -- served to anonymous callers.
That is the shape of defect this whole project keeps finding: not a bad line of code, but
an unexamined seam between two components that are each behaving as designed.

WHAT IT DELIBERATELY DOES NOT DO
It is a configuration reader, not an nginx interpreter. It does not evaluate `if`, `map`,
regex location precedence, or included files it was not given. It reports what a location
block publishes; it does not prove reachability, and it cannot see an access rule enforced
somewhere it is not reading.
"""
import json
import os
import re
import sys

# Framework-generated introspection surfaces. Publishing these is the finding.
INTROSPECTION = ("/docs", "/redoc", "/openapi.json", "/swagger", "/graphql")

_LOCATION = re.compile(r"location\s+([^\s{]+(?:\s+[^\s{]+)?)\s*\{")
_PROXY_PASS = re.compile(r"proxy_pass\s+(https?://[^;\s]+)\s*;")
_AUTH_DIRECTIVE = re.compile(r"\b(auth_basic|auth_request|satisfy|deny\s+all|internal)\b")


def _locations(src):
    """(match, body, line) for every location block, with brace tracking."""
    out = []
    for m in _LOCATION.finditer(src):
        depth, i = 1, m.end()
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        out.append((m.group(1).strip(), src[m.end():i - 1],
                    src[:m.start()].count("\n") + 1))
    return out


def _upstream_host(url):
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def scan_nginx(path, public_routes=None):
    """Findings for one nginx config. Returns (findings, unreadable_path_or_None)."""
    try:
        src = open(path, encoding="utf8", errors="replace").read()
    except OSError:
        return None, path             # unreadable: no answer, not "no findings"

    locs = _locations(src)
    if not locs:
        # A config with no location blocks is not necessarily wrong, but this lane has
        # nothing to say about it and must not imply it looked and found it clean.
        return [], None

    proxied = [(match, body, line, _PROXY_PASS.search(body))
               for match, body, line in locs]
    hosts = [_upstream_host(m.group(1)) for _, _, _, m in proxied if m]
    app_host = max(set(hosts), key=hosts.count) if hosts else None

    findings = []
    for match, body, line, pp in proxied:
        if not pp:
            continue
        guarded = bool(_AUTH_DIRECTIVE.search(body))

        norm = match.lstrip("~*= ").strip()
        if any(norm.startswith(i) for i in INTROSPECTION) and not guarded:
            findings.append({
                "tool": "nginx", "rule": "nginx/exposes-api-introspection",
                "file": os.path.basename(path), "line": line, "sev": "MEDIUM",
                "message": (f"`location {match}` publishes framework-generated API "
                            f"documentation through the edge with no access rule"),
                "remedy": ("gate it (auth_basic / auth_request / `internal`), restrict it "
                           "to a trusted network, or disable the generator in production "
                           "with docs_url=None and openapi_url=None. If public docs are "
                           "intended, declare those paths in the project's public routes "
                           "so it is a decision on the record."),
            })

        host = _upstream_host(pp.group(1))
        if app_host and host != app_host and not guarded:
            findings.append({
                "tool": "nginx", "rule": "nginx/proxies-backing-service",
                "file": os.path.basename(path), "line": line, "sev": "LOW",
                "message": (f"`location {match}` proxies straight to `{host}`, which is "
                            f"not the application upstream (`{app_host}`): a backing "
                            f"service is reachable through the edge"),
                "remedy": ("serve the objects through the application, or keep the direct "
                           "route read-only and scoped to one prefix and confirm the "
                           "service's own policy does not permit writes or listing"),
            })

        # A THIRD RULE WAS WRITTEN HERE AND DELETED, which is worth recording.
        # `nginx/undeclared-public-path` flagged every location whose path was not in the
        # project's declared public surface. On the real subject it fired seven times --
        # on /vehicles, /customers, /sales, /employees, /appointments -- all of which the
        # application authenticates itself. Proxying an authenticated route is correct, so
        # there was no attack to state and the realistic response to every one of those
        # findings was "yes, the app checks that", which is a suppression. A rule whose
        # remedy is a suppression teaches the model to write suppressions, and seven LOW
        # findings of pure load is the exact artefact this project criticises in others.
        # It failed the admission test in HARNESS-EXTENSION.md §5 and did not ship.
    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings, None


def scan_tree(root, public_routes=None):
    """Every nginx-looking config under `root`."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in {"__pycache__", ".git", "node_modules", ".venv"}]
        for fn in sorted(filenames):
            if not fn.endswith(".conf"):
                continue
            found, bad = scan_nginx(os.path.join(dirpath, fn), public_routes)
            if found is None:
                return None, bad
            for f in found:
                f["file"] = os.path.relpath(os.path.join(dirpath, fn), root)
            out += found
    return out, None


# ---------------------------------------------------------------------------
POS = """
server {
    listen 80;
    location /vehicles { proxy_pass http://api:8000; }
    location /customers { proxy_pass http://api:8000; }
    location /docs { proxy_pass http://api:8000; }
    location /openapi.json { proxy_pass http://api:8000; }
    location /minio/vehicles/ { proxy_pass http://minio:9000/vehicles/; }
}
"""

NEG = """
server {
    listen 80;
    location /vehicles { proxy_pass http://api:8000; }
    location /customers { proxy_pass http://api:8000; }
    location /health { proxy_pass http://api:8000; }
    # Documentation exists but is gated at the edge: this is the fix, not the defect.
    location /docs {
        auth_basic "staff only";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://api:8000;
    }
    # Static assets are served, not proxied to another service.
    location / { root /usr/share/nginx/html; }
}
"""


def _selftest():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        pos = os.path.join(td, "pos.conf")
        neg = os.path.join(td, "neg.conf")
        open(pos, "w").write(POS)
        open(neg, "w").write(NEG)

        pf, _ = scan_nginx(pos, public_routes={"/health", "/"})
        got = {f["rule"] for f in pf}
        for r in ["nginx/exposes-api-introspection", "nginx/proxies-backing-service"]:
            hit = r in got
            print(("[PASS] " if hit else "[FAIL] ") + f"positive control fires: {r}")
            ok = ok and hit
        two = len([f for f in pf if f["rule"] == "nginx/exposes-api-introspection"]) == 2
        print(("[PASS] " if two else "[FAIL] ")
              + "positive control: /docs AND /openapi.json both reported")
        ok = ok and two

        nf, _ = scan_nginx(neg, public_routes={"/health", "/"})
        got = {f["rule"] for f in nf}
        for label, r in [("an auth_basic-gated /docs is not a finding",
                          "nginx/exposes-api-introspection"),
                         ("a location that serves files rather than proxying is not a "
                          "backing-service exposure", "nginx/proxies-backing-service")]:
            clean = r not in got
            print(("[PASS] " if clean else "[FAIL] ") + f"negative control silent: {label}")
            ok = ok and clean

        missing = os.path.join(td, "nope.conf")
        f, bad = scan_nginx(missing)
        unm = f is None and bad is not None
        print(("[PASS] " if unm else "[FAIL] ")
              + "an unreadable config returns UNMEASURED, not zero findings")
        ok = ok and unm

        empty = os.path.join(td, "empty.conf")
        open(empty, "w").write("worker_processes 1;\n")
        f, _ = scan_nginx(empty)
        print(("[PASS] " if f == [] else "[FAIL] ")
              + "a config with no location blocks yields no findings and no crash")
        ok = ok and f == []
    print("\nall nginx-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    routes = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else None
    target = sys.argv[1]
    found, bad = (scan_tree(target, routes) if os.path.isdir(target)
                  else scan_nginx(target, routes))
    if found is None:
        print(f"UNMEASURED: {bad}")
        sys.exit(2)
    for f in found:
        print(f"  [{f['sev']:<6}] {f['rule']:<32} {f['file']}:{f['line']} — {f['message']}")
