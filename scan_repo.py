#!/usr/bin/env python3
"""Phase 2 pattern detector: scan a Go repository for weakness CANDIDATES.

Deterministic, stdlib+yaml only. Applies the detectors in vuln_patterns.yaml to every
non-vendored .go file and emits structured candidates (file:line, snippet, context,
category, severity, CWE, and a `refute` hint for the verifier). These are starting
points for adversarial verification, NOT confirmed vulnerabilities — the same discipline
as a raw oracle signal in Phase 1.

Usage:
    python scan_repo.py --repo /path/to/repo [--patterns vuln_patterns.yaml]
                        [--out artifacts/candidates.jsonl]
"""
import argparse
import json
import pathlib
import re

import yaml

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_PATTERNS = HERE / "vuln_patterns.yaml"
DEFAULT_OUT = HERE / "artifacts" / "candidates.jsonl"
SKIP_DIRS = {".git", "vendor", "node_modules", "testdata", ".idea", "dist", "build"}

# Positive/negative controls: each detector MUST fire on its vulnerable snippet and MUST NOT
# fire on its safe counterpart. This makes both "found X" and "found nothing" trustworthy --
# the same discipline as the ICE / opt-differential self-tests in Phase 1. (id, code, should_match)
SELFTEST_CASES = [
    ("sql_sprintf", 'q := fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)', True),
    ("sql_sprintf", 'rows, err := db.Query("SELECT * FROM users WHERE id=$1", id)', False),
    ("command_injection", 'exec.Command("sh", "-c", "ls "+dir)', True),
    ("command_injection", 'exec.Command("ls", "-la")', False),
    # The SECURE argument-separated form must NOT be flagged (regression: "args" != CWE-78).
    ("command_injection", 'c := exec.CommandContext(ctx, cmd, args...)', False),
    ("grpc_insecure", 'conn, _ := grpc.Dial(a, grpc.WithTransportCredentials(insecure.NewCredentials()))', True),
    ("grpc_insecure", 'conn, _ := grpc.Dial(a, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))', False),
    ("tls_insecure_skip", 'tls.Config{InsecureSkipVerify: true}', True),
    ("tls_insecure_skip", 'tls.Config{InsecureSkipVerify: false}', False),
    ("hardcoded_secret", 'apiKey = "sk-live-9f8a7b6c5d4e3f2a1b0c"', True),
    ("hardcoded_secret", 'apiKey = os.Getenv("API_KEY")', False),
    ("weak_crypto", 'import "crypto/md5"', True),
    ("weak_crypto", 'import "crypto/sha256"', False),
    ("insecure_rand", 'import "math/rand"', True),
    ("insecure_rand", 'import "crypto/rand"', False),
    ("path_traversal", 'f, err := os.Open(r.URL.Query().Get("file"))', True),
    ("path_traversal", 'f, err := os.Open("/etc/app/config.yaml")', False),
    ("missing_authz", '// TODO: add authorization check before serving', True),
    ("missing_authz", '// TODO: refactor this handler for clarity', False),
    ("unsafe_deserialize", 'dec := gob.NewDecoder(conn)', True),
    ("unsafe_deserialize", 'err := json.Unmarshal(body, &user)', False),
    ("ignored_error_security", 'VerifyToken(token)', True),
    ("ignored_error_security", 'defer conn.Close()', False),
    ("sensitive_logging", 'log.Printf("login for password=%s", pw)', True),
    ("sensitive_logging", 'log.Printf("login succeeded for user %s", name)', False),
    ("cors_wildcard", 'AllowOrigins: []string{"*"}', True),
    ("cors_wildcard", 'AllowOrigins: []string{"https://app.example.com"}', False),
    ("insecure_cookie", 'http.Cookie{Name: "sid", Value: v, Secure: false}', True),
    ("insecure_cookie", 'http.Cookie{Name: "sid", Value: v, Secure: true, HttpOnly: true}', False),
    ("debug_endpoint", 'import _ "net/http/pprof"', True),
    ("debug_endpoint", 'import "net/http"', False),
]


def load_patterns(path):
    data = yaml.safe_load(pathlib.Path(path).read_text())
    compiled = []
    for p in data.get("patterns", []):
        compiled.append({
            "id": p["id"], "category": p["category"], "cwe": p.get("cwe", ""),
            "severity": p.get("severity", "low"),
            "regexes": [re.compile(r) for r in p.get("any", [])],
            "rationale": p.get("rationale", ""), "refute": p.get("refute", ""),
        })
    return compiled


def iter_go_files(repo: pathlib.Path):
    for path in sorted(repo.rglob("*.go")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def classify_file(rel: str) -> str:
    low = rel.lower()
    if low.endswith("_test.go") or "/test" in low or low.startswith("test"):
        return "test"
    if "seed" in low or "fixture" in low or "example" in low or "mock" in low:
        return "fixture"
    return "source"


def scan_file(path: pathlib.Path, repo: pathlib.Path, patterns):
    rel = str(path.relative_to(repo))
    kind = classify_file(rel)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except Exception:  # noqa: BLE001
        return []
    hits = []
    for i, line in enumerate(lines):
        for pat in patterns:
            if any(rx.search(line) for rx in pat["regexes"]):
                ctx = "\n".join(lines[max(0, i - 2): i + 3])
                # Test/fixture files get a one-notch severity downgrade as a hint.
                sev = pat["severity"]
                if kind in ("test", "fixture") and sev in ("high", "medium"):
                    sev = {"high": "medium", "medium": "low"}[sev]
                hits.append({
                    "pattern_id": pat["id"], "category": pat["category"], "cwe": pat["cwe"],
                    "severity": sev, "base_severity": pat["severity"], "file_kind": kind,
                    "file": rel, "line": i + 1, "snippet": line.strip()[:240],
                    "context": ctx, "rationale": pat["rationale"], "refute": pat["refute"],
                })
    return hits


def pattern_fires(pat, code) -> bool:
    return any(rx.search(line) for line in code.splitlines() for rx in pat["regexes"])


def run_self_test(patterns) -> bool:
    by_id = {p["id"]: p for p in patterns}
    ok = True
    for pid, code, should in SELFTEST_CASES:
        pat = by_id.get(pid)
        got = pattern_fires(pat, code) if pat else False
        status = "PASS" if got == should else "FAIL"
        if got != should:
            ok = False
        kind = "vuln" if should else "safe"
        print(f"  [{status}] {pid:22s} ({kind}): fired={got} expected={should}")
    print("\ndetector self-test:", "PASS — all detectors sound" if ok else "FAIL — detector(s) broken")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo")
    ap.add_argument("--patterns", default=str(DEFAULT_PATTERNS))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--self-test", action="store_true",
                    help="verify each detector fires on a known-vulnerable snippet and stays "
                         "silent on a safe one, then exit")
    args = ap.parse_args()

    if args.self_test:
        raise SystemExit(0 if run_self_test(load_patterns(args.patterns)) else 1)
    if not args.repo:
        raise SystemExit("--repo is required (or use --self-test)")

    repo = pathlib.Path(args.repo).resolve()
    if not repo.is_dir():
        raise SystemExit(f"not a directory: {repo}")
    patterns = load_patterns(args.patterns)
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_hits, files_scanned = [], 0
    for gof in iter_go_files(repo):
        files_scanned += 1
        all_hits.extend(scan_file(gof, repo, patterns))

    with out_path.open("w", encoding="utf-8") as fh:
        for h in all_hits:
            fh.write(json.dumps(h) + "\n")

    by_cat, by_sev = {}, {}
    for h in all_hits:
        by_cat[h["category"]] = by_cat.get(h["category"], 0) + 1
        by_sev[h["severity"]] = by_sev.get(h["severity"], 0) + 1

    summary = out_path.parent / "scan-summary.md"
    lines = [f"# Pattern scan — `{repo.name}`", "",
             f"Go files scanned: {files_scanned}  |  candidates: **{len(all_hits)}**",
             "", "## By severity (hint, not verdict)", "", "| severity | count |", "|---|---:|"]
    for s in ("high", "medium", "low"):
        if by_sev.get(s):
            lines.append(f"| {s} | {by_sev[s]} |")
    lines += ["", "## By category", "", "| category | count |", "|---|---:|"]
    for c in sorted(by_cat):
        lines.append(f"| {c} | {by_cat[c]} |")
    lines += ["", "_Candidates are unverified. Each must survive adversarial verification "
              "(reachable? attacker-controlled? production vs fixture?) before it is a finding._"]
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"scanned {files_scanned} Go files -> {len(all_hits)} candidates")
    print(f"  by severity: {by_sev}")
    print(f"  by category: {by_cat}")
    print(f"  candidates: {out_path}")
    print(f"  summary:    {summary}")


if __name__ == "__main__":
    main()
