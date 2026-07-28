#!/usr/bin/env python3
"""Security oracle for a REPOSITORY rather than a single file, with a frontend lane.

The note-sharing study measured one `app.py`. A real project is a tree: several Python
modules, a template or bundle the browser executes, and a server config. Three things
change, and each of them is a place the single-file oracle would have quietly lied:

  1. MEASURABILITY IS PER-FILE NOW. One module that does not parse silences every
     AST-based engine for that module while the rest of the tree still reports findings,
     so the total falls and reads as progress. `analyzable` is therefore the conjunction
     over every Python file, and the offending file is named.

  2. THE BROWSER IS AN EXECUTION ENVIRONMENT THE PYTHON LANES CANNOT SEE. bandit and
     CodeQL's Python suites scan .py. A stored XSS lives in an inline <script> that
     interpolates server data into innerHTML, and both engines score that file at zero
     because they never open it. A frontend lane is not a nicety here; without it the
     repository's most reachable vulnerability is invisible to the loop by construction.

  3. LANES MUST BE RECORDED, NOT ASSUMED. Same doctrine as the single-file oracle: a lane
     that fails to run removes its whole rule class, which is indistinguishable from a
     clean result to a gate that reads only totals.

Semgrep is deliberately NOT used here. It is the held-out auditor in this line of work and
must never enter a repair loop, or its agreement with the in-loop battery stops being
evidence of anything.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import repo_authz  # noqa: E402
import repo_fastapi  # noqa: E402
import repo_nginx  # noqa: E402
import repo_practice  # noqa: E402

SEV_W = {"HIGH": 3, "ERROR": 3, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 1}
SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}


def py_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def web_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith((".html", ".htm", ".js")):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


# ---------------------------------------------------------------------------
# The frontend lane.
#
# Scope note, stated plainly because a hand-written lane is the easiest thing in a study
# like this to over-claim: this is a SINK lane, not a taint engine. It flags a dynamic
# HTML sink fed by an interpolation that is not demonstrably inert, plus two config-level
# defects (session token in web storage, absent CSP). It does not prove reachability, and
# it will not find an XSS routed through a helper it cannot follow. Every rule below is
# paired with a negative control in --selftest so a suppression cannot silently widen.
# ---------------------------------------------------------------------------
SINKS = r"(innerHTML|outerHTML|insertAdjacentHTML|document\.write(?:ln)?)"

# Interpolations that cannot carry markup: numbers, escaped values, encoded URIs, and
# calls whose result is numeric. Anything else in an HTML sink is treated as live.
INERT = re.compile(
    r"^\s*(?:"
    r"\d+(?:\.\d+)?"                                    # a numeric literal
    r"|['\"][^'\"<>&]*['\"]"                             # a string literal carrying no markup
    # an escaping or numeric-formatting call: the whole call, not just its opening paren.
    # toLocaleString/toFixed are here deliberately -- a lane that flags number formatting
    # generates exactly the non-exploitable load this line of work criticises elsewhere.
    r"|(?:escapeHtml|escape|encodeURIComponent|encodeURI|Number|parseInt|parseFloat)\s*\(.*\)"
    r"|[\w$.?\[\]]+\s*\.\s*(?:toLocaleString|toFixed)\s*\([^)]*\)(?:\s*\|\|\s*\d+)?"
    r"|[\w$.?\[\]]+\s*\.\s*length"                       # a collection length is a number
    # a ternary whose two branches are both markup-free literals, whatever the condition
    r"|[^?]+\?\s*['\"][^'\"<>]*['\"]\s*:\s*['\"][^'\"<>]*['\"]"
    r")\s*$"
)


def _interpolations(text):
    """Yield the expressions inside ${...} of a template literal, brace-balanced."""
    out, i = [], 0
    while True:
        j = text.find("${", i)
        if j < 0:
            return out
        depth, k = 1, j + 2
        while k < len(text) and depth:
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
            k += 1
        out.append(text[j + 2:k - 1])
        i = k


def _template_literals(src):
    """Every backtick template literal in `src`, as (start_line, text).

    Line-based scanning is not enough and the reason is the whole point of this lane: the
    markup that carries the injection is usually assembled in a multi-line template that a
    helper RETURNS, and the innerHTML assignment that consumes it is somewhere else
    entirely. Matching only where sink and interpolation share a line finds the harmless
    one-liners and misses the card renderer.
    """
    out, i, line = [], 0, 1
    while i < len(src):
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "`":
            start, start_line, i = i + 1, line, i + 1
            depth = 0
            while i < len(src):
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "\n":
                    line += 1
                elif src[i] == "{" and src[i - 1] == "$":
                    depth += 1
                elif src[i] == "}" and depth:
                    depth -= 1
                elif src[i] == "`" and not depth:
                    break
                i += 1
            out.append((start_line, src[start:i]))
        i += 1
    return out


MARKUP = re.compile(r"<[a-zA-Z/]")


def scan_frontend(path):
    """Findings for one .html/.js file."""
    src = open(path, encoding="utf8", errors="replace").read()
    lines = src.splitlines()
    findings = []
    lower = src.lower()

    # (a) markup assembled by interpolation. Reported once per literal, at its opening
    # line, so a 20-line card renderer is one finding to fix rather than eight.
    for start_line, lit in _template_literals(src):
        if not MARKUP.search(lit):
            continue
        live = [e for e in _interpolations(lit) if not INERT.match(e)]
        if not live:
            continue
        findings.append({
            "tool": "frontend", "rule": "js/html-from-interpolation", "file": path,
            "line": start_line, "sev": "HIGH",
            "message": ("markup built by interpolating "
                        + ", ".join("`" + e.strip()[:32] + "`" for e in live[:3])
                        + (" and others" if len(live) > 3 else "")),
            "remedy": "build the node with textContent / createElement, or escape each "
                      "interpolated value; do not blocklist payloads",
        })
        # an interpolation landing inside an attribute value is injectable on its own
        for m in re.finditer(r"(src|href|style|on\w+)\s*=\s*[\"']([^\"']*)", lit):
            if "${" in m.group(2):
                findings.append({
                    "tool": "frontend", "rule": "js/attribute-injection", "file": path,
                    "line": start_line + lit[:m.start()].count("\n"), "sev": "MEDIUM",
                    "message": f"value interpolated into the `{m.group(1)}` attribute",
                    "remedy": "validate against an allow-list, or set the property through "
                              "the DOM API instead of building attribute text",
                })
                break

    for n, line in enumerate(lines, 1):
        # (b) a sink fed something that is NOT a template literal. Extract the
        # right-hand side explicitly rather than with a lookahead: `\\s*` backtracks, so
        # `=\\s*(?![`\'"])` happily matches by consuming no whitespace and then finding a
        # space, and every template assignment gets counted a second time. Double-counting
        # is not a harmless bug in this study -- inflated analyzer load is the precise
        # artefact the work criticises elsewhere.
        m = re.search(SINKS + r"\\s*=\\s*(.+)$", line)
        if m:
            rhs = m.group(2).strip().rstrip(";").strip()
            covered = rhs.startswith("`") or ".map(" in rhs or "${" in rhs
            if rhs and not covered and not INERT.match(rhs):
                findings.append({
                    "tool": "frontend", "rule": "js/dom-xss-sink", "file": path,
                    "line": n, "sev": "HIGH",
                    "message": f"`{rhs[:50]}` assigned to an HTML sink",
                    "remedy": "assign with textContent, or escape before innerHTML",
                })
        if re.search(r"(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['\"][^'\"]*"
                     r"(token|jwt|auth|session)", line, re.I):
            findings.append({
                "tool": "frontend", "rule": "js/session-token-in-web-storage",
                "file": path, "line": n, "sev": "MEDIUM",
                "message": "session token stored in web storage, readable by any script",
                "remedy": "hold the session in an HttpOnly, Secure, SameSite cookie so a "
                          "script-level compromise cannot read it",
            })

    if "<html" in lower and "content-security-policy" not in lower:
        findings.append({
            "tool": "frontend", "rule": "html/no-csp", "file": path, "line": 1,
            "sev": "LOW",
            "message": "document ships no Content-Security-Policy",
            "remedy": "serve a CSP that forbids inline script, or set it in the web server",
        })
    return findings


def scan_bandit(root):
    """bandit over the tree. Returns (findings, ran)."""
    try:
        r = subprocess.run(["bandit", "-r", root, "-f", "json", "-q",
                            "-x", ",".join(SKIP_DIRS)],
                           capture_output=True, text=True, timeout=300)
        data = json.loads(r.stdout or "{}")
    except Exception:
        return [], False
    out = []
    for f in data.get("results", []):
        out.append({
            "tool": "bandit", "rule": f.get("test_id", "B000"),
            "file": os.path.relpath(f.get("filename", ""), root),
            "line": f.get("line_number", 0),
            "sev": f.get("issue_severity", "LOW").upper(),
            "message": f.get("issue_text", ""),
            "remedy": f.get("issue_cwe", {}).get("link", ""),
        })
    return out, True


def scan_codeql(root, codeql="codeql"):
    """CodeQL python-security suite over the tree. Returns (findings, ran)."""
    import shutil as _sh
    if not _sh.which(codeql):
        return [], False
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "db")
        sarif = os.path.join(td, "out.sarif")
        try:
            c1 = subprocess.run([codeql, "database", "create", db, "--language=python",
                                 f"--source-root={root}", "--overwrite"],
                                capture_output=True, text=True, timeout=1800)
            if c1.returncode != 0:
                return [], False
            c2 = subprocess.run(
                [codeql, "database", "analyze", db,
                 "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
                 "--format=sarifv2.1.0", f"--output={sarif}", "--rerun"],
                capture_output=True, text=True, timeout=1800)
            if c2.returncode != 0 or not os.path.exists(sarif):
                return [], False
            data = json.load(open(sarif))
        except Exception:
            return [], False
    out = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            out.append({
                "tool": "codeql", "rule": res.get("ruleId", "?"),
                "file": loc.get("artifactLocation", {}).get("uri", ""),
                "line": loc.get("region", {}).get("startLine", 0),
                "sev": res.get("level", "warning").upper(),
                "message": (res.get("message") or {}).get("text", ""),
                "remedy": "",
            })
    return out, True


def assess_repo(root, use_codeql=True, use_frontend=True, use_authz=True,
                use_practice=True, use_fastapi=True, use_nginx=True,
                public_routes=None):
    """The repository's security state, with every lane's status recorded.

    GENERATION NOTE. `use_fastapi` and `use_nginx` add two lanes that did not exist when
    the study-2 corpus was scored, so a run with them on is NOT comparable to a stored
    number from before them: on the brownfield subject they add 3 findings and 8 weighted
    load that were always there and that nothing could see. Pass both False to reproduce a
    pre-existing score exactly. Adding a lane changes the instrument, and an instrument
    change is a new generation, not a bug fix -- that distinction is the paper.
    """
    root = os.path.abspath(root)
    # (1) parse every module first: one unparseable file silences a lane for that file
    for p in py_files(root):
        try:
            ast.parse(open(p, encoding="utf8", errors="replace").read())
        except SyntaxError as e:
            return {"findings": [], "weighted": None, "analyzable": False,
                    "parse_error": f"{os.path.relpath(p, root)}:{e.lineno}: {e.msg}",
                    "lanes": {}, "lanes_ran": False}

    findings, lanes = [], {}
    b, ran = scan_bandit(root)
    lanes["bandit"] = ran
    findings += b
    if use_codeql:
        q, ran = scan_codeql(root)
        lanes["codeql"] = ran
        findings += q
    if use_frontend:
        try:
            for p in web_files(root):
                for f in scan_frontend(p):
                    f["file"] = os.path.relpath(f["file"], root)
                    findings.append(f)
            lanes["frontend"] = True
        except Exception:
            lanes["frontend"] = False

    if use_authz:
        az, bad = repo_authz.scan_authz(root)
        # The lane returns None rather than [] when a module will not parse: an
        # authorization answer it could not compute must never read as "authorized".
        lanes["authz"] = az is not None
        findings += az or []

    if use_fastapi:
        fa, bad = repo_fastapi.scan_fastapi(root, public_routes=public_routes)
        lanes["fastapi"] = fa is not None
        findings += fa or []

    if use_nginx:
        ng, bad = repo_nginx.scan_tree(root, public_routes=public_routes)
        lanes["nginx"] = ng is not None
        findings += ng or []

    if use_practice:
        pr, bad = repo_practice.scan_practice(root)
        lanes["practice"] = pr is not None
        # DEDUP ACROSS LANES. The practice lane's "this handler is guarded differently
        # from its siblings" and the authz lane's "this handler has no authentication"
        # fire on the same line for the same defect, from two angles. Counting both
        # doubles the load and hands the model the same fix twice -- the inflated-load
        # artefact this project criticises, produced by our own instruments.
        seen = {(f["file"], f["line"]) for f in findings}
        findings += [f for f in (pr or []) if (f["file"], f["line"]) not in seen]

    weighted = sum(SEV_W.get(f["sev"], 1) for f in findings)
    findings.sort(key=lambda f: (-SEV_W.get(f["sev"], 1), f["tool"], f["file"], f["line"]))
    return {"findings": findings, "weighted": weighted, "analyzable": True,
            "parse_error": None, "lanes": lanes,
            "lanes_ran": all(lanes.values()) and bool(lanes)}


# ---------------------------------------------------------------------------
POS = """<html><body><script>
localStorage.setItem('token', authToken);
// THE REGRESSION CASE: sink and interpolation never share a line. A helper returns the
// markup and the caller assigns it, which is how the real renderer in this corpus is
// written and what a line-based lane silently missed.
function card(v) {
  return `
    <div class="card">
      <img src="${v.image}" alt="pic">
      <div class="title">${v.make} ${v.model}</div>
    </div>`;
}
grid.innerHTML = items.map(card).join('');
</script></body></html>"""

NEG = """<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'">
</head><body><script>
grid.textContent = v.make;
el.innerHTML = `<div>${escapeHtml(v.make)}</div>`;
el.innerHTML = `<div>${Number(v.year)}</div>`;
el.innerHTML = `<span>${v.is_new ? 'New' : 'Used'}</span>`;
el.innerHTML = `<div>${v.mileage?.toLocaleString() || 0}</div>`;
el.innerHTML = `<div>${list.length}</div>`;
el.innerHTML = `<option ${m === cur ? 'selected' : ''}>x</option>`;
sessionStorage.setItem('theme', 'dark');
</script></body></html>"""


def _selftest():
    """Positive and negative controls for the frontend lane.

    Paired the way the security-oracle controls are: every suppression that keeps a false
    positive out is matched against a real defect it must still catch, so tightening a
    rule cannot silently blind the lane.
    """
    ok = True
    with tempfile.TemporaryDirectory() as td:
        pos = os.path.join(td, "pos.html")
        neg = os.path.join(td, "neg.html")
        open(pos, "w").write(POS)
        open(neg, "w").write(NEG)
        pf = scan_frontend(pos)
        nf = scan_frontend(neg)
        want_pos = {"js/html-from-interpolation", "js/session-token-in-web-storage",
                    "js/attribute-injection", "html/no-csp"}
        got_pos = {f["rule"] for f in pf}
        for r in sorted(want_pos):
            hit = r in got_pos
            print(("[PASS] " if hit else "[FAIL] ") + f"positive control fires: {r}")
            ok = ok and hit
        got_neg = {f["rule"] for f in nf}
        for label, r in [("textContent is not a sink", "js/html-from-interpolation"),
                         ("escaped/numeric/ternary interpolation is inert",
                          "js/html-from-interpolation"),
                         ("a non-session storage key is not a finding",
                          "js/session-token-in-web-storage"),
                         ("a document with a CSP is not flagged", "html/no-csp")]:
            clean = r not in got_neg
            print(("[PASS] " if clean else "[FAIL] ") + f"negative control silent: {label}")
            ok = ok and clean
    print("\nall frontend-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    target = sys.argv[1]

    # GENERATION IS EXPLICIT ON THE COMMAND LINE, because adding a lane changes the number
    # and a changed number with no marker is how a corpus quietly stops being comparable.
    # `--gen2` pins the lane set the study-2 corpus was scored with; the default is current.
    gen2 = "--gen2" in sys.argv
    routes = None
    for a in sys.argv[2:]:
        if a.startswith("--public-routes="):
            routes = set(a.split("=", 1)[1].split(","))
    if routes is None and not gen2:
        # Take the declared public surface from the project profile when one is available,
        # so the introspection rule has the fact it needs instead of being skipped.
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))))
            from packlib import load_policy
            routes = set(load_policy(os.environ.get("HARNESS_PROFILE", "dealership"),
                                     root=target).fact("public_routes"))
        except Exception:
            routes = None

    a = assess_repo(target, use_codeql="--codeql" in sys.argv,
                    use_fastapi=not gen2, use_nginx=not gen2, public_routes=routes)
    gen = "gen2 (study-2 corpus lane set)" if gen2 else "current"
    print(f"generation: {gen}   public_routes: "
          f"{'declared' if routes else 'UNAVAILABLE (introspection rule skipped)'}")
    print(f"lanes: {a['lanes']}  analyzable: {a['analyzable']}  weighted: {a['weighted']}  "
          f"findings: {len(a['findings'])}")
    for f in a["findings"]:
        print(f"  [{f['sev']:6s}] {f['tool']:8s} {f['rule']:34s} {f['file']}:{f['line']} — "
              f"{f['message'][:70]}")
