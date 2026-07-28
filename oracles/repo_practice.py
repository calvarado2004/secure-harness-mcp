#!/usr/bin/env python3
"""The practice lane: invariants an experienced engineer applies that no scanner encodes.

WHY THIS LEG EXISTS
Opus 4.8, given a finding that the session token sat in web storage, wrote exactly the
remedy a reviewer would want -- `document.cookie = token; Secure; SameSite=Strict` -- and
then never read the cookie back, leaving the initialiser pointed at a localStorage key
nothing writes. The security knowledge was right. What was missing is the thing a senior
engineer supplies in ten seconds: IF YOU MOVE WHERE STATE LIVES, MOVE THE READ PATH TOO.
No security scanner encodes that, and no functional probe of an API surface sees it.

THE ADMISSION TEST, ENFORCED IN THE DATA
Security rules must answer "can you state the attack?". A practice rule must answer the
analogous question: CAN YOU STATE THE FAILURE THIS PREVENTS? Every rule below carries a
`failure` field, and `--selftest` refuses to pass if any rule ships without one. That is
deliberate: without it this lane decays into a style linter, generates precisely the
non-exploitable load this project criticises, and teaches the model to write suppressions.

Rules earn their place by having cost someone something real. Three of the four below were
derived from defects observed in this project's own runs, and the provenance is recorded
in each `failure` string rather than in a commit message nobody reads.
"""
import ast
import json
import os
import re
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}
SENSITIVE = {"Customer", "Employee", "Sale", "User", "Appointment"}
AUTH_DEPS = {"get_current_user", "get_current_active_user", "require_user",
             "require_admin", "get_admin_user", "verify_token"}
# Shared with the authorization lane so the project declares its public surface ONCE. A
# divergence rule without this fires on every deliberately-anonymous endpoint and teaches
# the practitioner to ignore the lane -- which is how a rule set dies.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_authz import PUBLIC_ROUTES, _router_prefix, _handlers  # noqa: E402


def _files(root, exts):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(exts):
                out.append(os.path.join(dirpath, fn))
    return out


def _scripts(src):
    return "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", src, re.S | re.I))


# ---------------------------------------------------------------------------
# R1 — state that is written but never read, or read but never written.
# ---------------------------------------------------------------------------
def _r1_half_wired_state(path, src, js):
    findings = []
    stores = r"(?:localStorage|sessionStorage)"
    written = set(re.findall(stores + r"\s*\.\s*setItem\s*\(\s*['\"]([^'\"]+)['\"]", js))
    read = set(re.findall(stores + r"\s*\.\s*getItem\s*\(\s*['\"]([^'\"]+)['\"]", js))
    removed = set(re.findall(stores + r"\s*\.\s*removeItem\s*\(\s*['\"]([^'\"]+)['\"]", js))
    cookie_set = set(re.findall(r"document\.cookie\s*=\s*[`'\"]?\s*\$?\{?\s*([A-Za-z_][\w]*)"
                                r"\s*\}?\s*=", js))
    cookie_set |= set(re.findall(r"document\.cookie\s*=\s*[`'\"]([A-Za-z_][\w]*)=", js))
    cookie_read = "document.cookie" in js.replace("document.cookie =", "")

    for key in sorted((read | removed) - written):
        findings.append(_f(path, _line_of(src, key), "practice/half-wired-state", "HIGH",
                           f"`{key}` is read or cleared in web storage but never written",
                           "wire the read and the write together, or remove both; a "
                           "persistence path that only half exists silently loses state",
                           "a user is logged out on every page load while every security "
                           "check still passes (observed: two of three arms, gen-1)"))
    if cookie_set and not cookie_read:
        findings.append(_f(path, _line_of(src, "document.cookie"),
                           "practice/write-without-read", "HIGH",
                           "a cookie is written but nothing ever reads it back",
                           "read the value where the session is restored, not only where "
                           "it is stored",
                           "the fix looks correct in review and does nothing at runtime "
                           "(observed: Opus 4.8 wrote a Secure/SameSite cookie it never "
                           "read, gen-1)"))
    return findings


# ---------------------------------------------------------------------------
# R2 — a network call whose failure is never handled.
# ---------------------------------------------------------------------------
def _r2_unchecked_fetch(path, src, js):
    findings = []
    for m in re.finditer(r"\bawait\s+fetch\s*\(", js):
        seg = js[m.start():m.start() + 400]
        if not re.search(r"\.ok\b|\.status\b|catch\s*\(|throw\b", seg):
            findings.append(_f(path, _line_of(src, js[m.start():m.start() + 40]),
                               "practice/unchecked-response", "MEDIUM",
                               "a fetch result is used without checking whether it "
                               "succeeded",
                               "check `res.ok` (or the status) before using the body, and "
                               "surface the failure to the user",
                               "a 500 from the API renders as an empty page rather than "
                               "an error, so outages look like missing data"))
    return findings


# ---------------------------------------------------------------------------
# R3 — the same resource reached through paths that guard it differently.
# ---------------------------------------------------------------------------
def _r3_divergent_access(root):
    """Handlers returning the same sensitive resource, some guarded and some not."""
    by_model = {}
    for path in _files(root, (".py",)):
        rel = os.path.relpath(path, root)
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None
        prefix = _router_prefix(tree)
        for method, route, node, dec in _handlers(tree):
            if ((prefix + route) or "/") in PUBLIC_ROUTES:
                continue
            dump = ast.dump(node)
            guarded = any(f"id='{d}'" in dump for d in AUTH_DEPS)
            for model in SENSITIVE:
                if f"id='{model}'" in dump:
                    by_model.setdefault(model, []).append(
                        (rel, node.name, node.lineno, guarded))
    out = []
    for model, handlers in sorted(by_model.items()):
        guarded = [h for h in handlers if h[3]]
        open_ = [h for h in handlers if not h[3]]
        if guarded and open_:
            for rel, name, line, _ in open_:
                out.append(_f(rel, line, "practice/divergent-resource-access", "HIGH",
                              f"`{name}` reaches {model} without the guard that "
                              f"{len(guarded)} other handler(s) of {model} apply",
                              f"route every path that returns {model} through one "
                              f"authorization helper, so a new path cannot forget it",
                              "the forgotten second path becomes the vulnerability -- an "
                              "IDOR shipped through /export in this project's other study "
                              "while the primary read path was correctly guarded"))
    return out


# ---------------------------------------------------------------------------
# R4 — user data rendered through inconsistent paths in one file.
# ---------------------------------------------------------------------------
def _r4_inconsistent_render(path, src, js):
    safe = len(re.findall(r"\.textContent\s*=", js))
    raw = len(re.findall(r"\.innerHTML\s*=", js))
    if safe and raw:
        return [_f(path, 1, "practice/inconsistent-render-path", "MEDIUM",
                   f"user data is rendered two ways in one file "
                   f"({safe} via textContent, {raw} via innerHTML)",
                   "render through a single helper so a new call site cannot pick the "
                   "unsafe path by accident",
                   "the one render you forget to escape is the stored XSS; mixed "
                   "conventions guarantee there will eventually be one")]
    return []


def _f(file, line, rule, sev, message, remedy, failure):
    return {"tool": "practice", "rule": rule, "file": file, "line": line, "sev": sev,
            "message": message, "remedy": remedy, "failure": failure}


def _line_of(src, needle):
    for i, line in enumerate(src.splitlines(), 1):
        if needle and needle in line:
            return i
    return 1


def scan_practice(root):
    """All practice findings for the tree, or (None, file) if something will not parse."""
    root = os.path.abspath(root)
    findings = []
    div = _r3_divergent_access(root)
    if div is None:
        return None, "python source does not parse"
    findings += div
    for path in _files(root, (".html", ".htm", ".js")):
        rel = os.path.relpath(path, root)
        src = open(path, encoding="utf8", errors="replace").read()
        js = _scripts(src) or src
        findings += _r1_half_wired_state(rel, src, js)
        findings += _r2_unchecked_fetch(rel, src, js)
        findings += _r4_inconsistent_render(rel, src, js)
    return findings, None


# ---------------------------------------------------------------------------
GOOD_JS = """<html><body><script>
let token = localStorage.getItem('t');
function save(v){ localStorage.setItem('t', v); }
function clear(){ localStorage.removeItem('t'); }
async function load(){
  const res = await fetch('/x');
  if (!res.ok) throw new Error('failed');
  el.textContent = (await res.json()).name;
}
</script></body></html>"""

BAD_JS = """<html><body><script>
let token = localStorage.getItem('t');
function clear(){ localStorage.removeItem('t'); }
async function load(){
  const res = await fetch('/x');
  const d = await res.json();
  el.innerHTML = `<b>${d.name}</b>`;
  other.textContent = d.id;
}
</script></body></html>"""


def _selftest():
    import tempfile
    ok = True
    here = os.path.dirname(os.path.abspath(__file__))
    base = os.path.join(os.path.dirname(here), "car_dealership_original_code")

    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "bad.html"), "w").write(BAD_JS)
        bad, _ = scan_practice(td)
        got = {f["rule"] for f in bad}
        for rule in ["practice/half-wired-state", "practice/unchecked-response",
                     "practice/inconsistent-render-path"]:
            hit = rule in got
            print(("[PASS] " if hit else "[FAIL] ") + f"positive control: {rule}")
            ok = ok and hit
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "good.html"), "w").write(GOOD_JS)
        good, _ = scan_practice(td)
        for label in ["coherent storage is not flagged", "a checked fetch is not flagged",
                      "a single render path is not flagged"]:
            clean = not good
            print(("[PASS] " if clean else "[FAIL] ")
                  + f"negative control: {label}"
                  + ("" if clean else f" -> {[f['rule'] for f in good]}"))
            ok = ok and clean

    # R3 fires on the real repository, where guarded and unguarded paths coexist.
    real, _ = scan_practice(base)
    hit = any(f["rule"] == "practice/divergent-resource-access" for f in real)
    print(("[PASS] " if hit else "[FAIL] ")
          + "positive control (real repo): practice/divergent-resource-access")
    ok = ok and hit

    # THE ADMISSION TEST, MECHANICALLY ENFORCED.
    missing = [f["rule"] for f in real if not f.get("failure")]
    print(("[PASS] " if not missing else "[FAIL] ")
          + "every practice rule names the failure it prevents"
          + ("" if not missing else f" -> {sorted(set(missing))}"))
    ok = ok and not missing

    print("\nall practice-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    fs, bad = scan_practice(sys.argv[1])
    if bad:
        print(f"unmeasured: {bad}")
        sys.exit(2)
    print(f"{len(fs)} practice findings")
    for f in fs:
        print(f"  [{f['sev']:6s}] {f['rule']:38s} {f['file']}:{f['line']}\n"
              f"           {f['message']}\n           prevents: {f['failure']}")
