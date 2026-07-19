#!/usr/bin/env python3
"""secure-proxy: the verify-and-repair harness as a transparent, OpenAI-compatible inference layer.

Point any client (Qwen Code, Cursor, Continue, curl) at this endpoint instead of the raw model. On
every /v1/chat/completions response that contains a Go or Python code block, the proxy runs the
research harness --- build + security-scan the generated code, and if it fails to compile or trips a
detector, feed the specific errors back to the *same* upstream model and regenerate (up to N times)
--- then splices the hardened code back into the response and appends an HONEST residual note. Code
that already builds clean passes through untouched, so extra compute is spent only on risky output.

This operationalizes the thesis: the guides alone are a trap (security up, robustness down); only the
LOOP delivers both. The proxy enforces the loop in the serving path, so a consumer model cannot opt
out of it. It is a strong filter, NOT a proof of security: residual findings the detectors cannot see
remain, and some weaknesses (e.g. OS command injection) resist the loop --- the note says so plainly.

Run:   SECURE_PROXY_UPSTREAM=http://192.168.1.88:8081/v1 python secure_proxy.py --port 8090
Test:  python secure_proxy.py --self-test        (offline: checks the assessors, no network)
Deps:  stdlib only; `go` on PATH (Go build), `bandit` (Python scan); scan_repo.py for Go detectors.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate as gen          # build_and_scan (Go), extract_code  # noqa: E402
import pyharness as pyh         # py_build_scan (Python via bandit)   # noqa: E402

SCANNER = HERE / "scan_repo.py"
GO_SECURE_SYS = (HERE / "secure_system_prompt.txt").read_text()
PY_SECURE_SYS = (HERE / "py_secure_prompt.txt").read_text()

UPSTREAM = os.environ.get("SECURE_PROXY_UPSTREAM", "http://localhost:8080/v1").rstrip("/")
KEY = os.environ.get("SECURE_PROXY_KEY", "dummy")
MAX_ITERS = int(os.environ.get("SECURE_PROXY_MAX_ITERS", "2"))

FENCE = re.compile(r"```(go|golang|python|py)[^\n]*\n(.*?)```", re.DOTALL | re.IGNORECASE)
LANG = {"go": "go", "golang": "go", "python": "python", "py": "python"}

# bandit advisory-only tests: import notice (B404) and safe-subprocess heuristics (B603 no-shell,
# B607 partial path). These fire on ANY subprocess use regardless of input validation and cannot be
# cleared without a `# nosec` comment, so treating them as vulnerabilities makes the repair loop
# chase an unwinnable target. GENUINE command injection is shell=True (B602) / shell (B605), which
# are NOT listed here and stay blocking. Documented false-positive quarantine, per the methodology
# that quarantines Go's secure exec.Command(bin, args...) form.
BANDIT_ADVISORY = {"B404", "B603", "B607"}


# --------------------------------------------------------------------------- assessors
def assess(lang, code):
    """Return (builds, build_err, findings[list of {cwe,severity,why}]) for a snippet."""
    if lang == "go":
        ok, err, _ = gen.build_and_scan(code)
        findings = []
        with tempfile.TemporaryDirectory(prefix="sp-go-") as tmp:
            wd = pathlib.Path(tmp)
            (wd / "snippet.go").write_text(code)
            cand = wd / "c.jsonl"
            subprocess.run([sys.executable, str(SCANNER), "--repo", str(wd), "--out", str(cand)],
                           capture_output=True, timeout=60)
            if cand.exists():
                for line in cand.read_text().splitlines():
                    if line.strip():
                        r = json.loads(line)
                        findings.append({"cwe": r.get("cwe", ""), "severity": r.get("severity", ""),
                                         "why": r.get("rationale", "")[:80], "line": r.get("line")})
        return ok, err, findings
    # python
    compiles, cerr, findings, _w = pyh.py_build_scan(code)
    blocking = [f for f in findings if f.get("test") not in BANDIT_ADVISORY]  # quarantine advisories
    return compiles, cerr, [{"cwe": f.get("cwe", ""), "severity": f.get("severity", ""),
                             "why": f.get("why", ""), "line": f.get("line"),
                             "test": f.get("test")} for f in blocking],


def _problems(builds, err, findings):
    probs = []
    if not builds:
        probs.append(f"It does not compile:\n{err[:500]}")
    if findings:
        probs.append("A security scan flagged:\n" + "\n".join(
            f"- {f['severity']} {f['cwe']} (line {f['line']}): {f['why']}" for f in findings))
    return probs


# --------------------------------------------------------------------------- upstream
def upstream_chat(model, messages, temperature=0.3, max_tokens=1400):
    body = json.dumps({"model": model, "messages": messages, "temperature": temperature,
                       "max_tokens": max_tokens,
                       "chat_template_kwargs": {"enable_thinking": False}}).encode()
    req = urllib.request.Request(f"{UPSTREAM}/chat/completions", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {KEY}"})
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            m = d["choices"][0]["message"]
            return m.get("content") or m.get("reasoning") or ""
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < 3:
                time.sleep(2 ** attempt)
    raise last


def repair_loop(lang, model, intent, code, iters):
    """Harden `code` via the verify-and-repair loop. Returns (code, builds, findings, n_iters)."""
    sys_prompt = GO_SECURE_SYS if lang == "go" else PY_SECURE_SYS
    done_iters = 0
    for _ in range(iters):
        r = assess(lang, code)
        builds, err, findings = r[0], r[1], r[2]
        if builds and not findings:
            return code, builds, findings, done_iters
        probs = _problems(builds, err, findings)
        fence = "go" if lang == "go" else "python"
        fix = (f"{intent}\n\nYour previous solution had problems:\n" + "\n".join(probs)
               + f"\n\nReturn a corrected version that compiles and resolves every issue. "
               f"Output only {fence} code in one ```{fence} block.")
        code = gen.extract_code(upstream_chat(model, [{"role": "system", "content": sys_prompt},
                                                      {"role": "user", "content": fix}]))
        done_iters += 1
    r = assess(lang, code)
    return code, r[0], r[2], done_iters


# --------------------------------------------------------------------------- harden a completion
def harden_content(content, model, intent):
    """Find the primary Go/Python code block, harden it, splice back, append an honest note."""
    m = FENCE.search(content)
    if not m:
        return content, None  # nothing to harden
    lang = LANG[m.group(1).lower()]
    orig = m.group(2)
    before = assess(lang, orig)
    if before[0] and not before[2]:
        note = f"secure-proxy: {lang} code builds clean, 0 findings (no repair needed)."
        return content, note
    hardened, builds, findings, iters = repair_loop(lang, model, intent, orig, MAX_ITERS)
    spliced = content[:m.start()] + f"```{lang}\n{hardened}\n```" + content[m.end():]
    if builds and not findings:
        note = f"secure-proxy: hardened via verify-and-repair ({iters} iter). builds=true, 0 residual findings."
    else:
        resid = ", ".join(sorted({str(f["cwe"]) for f in findings if f["cwe"]})) or "unresolved build error"
        note = (f"secure-proxy: hardened ({iters} iter), but NOT fully clean. builds={str(builds).lower()}, "
                f"residual: {resid}. Review before use — this is a filter, not a guarantee.")
    return spliced + f"\n\n> \U0001F6E1️ {note}", note


# --------------------------------------------------------------------------- HTTP handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quieter
        sys.stderr.write("[secure-proxy] " + (a[0] % a[1:]) + "\n")

    def _send(self, code, obj, ctype="application/json"):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            try:
                req = urllib.request.Request(f"{UPSTREAM}/models",
                                             headers={"Authorization": f"Bearer {KEY}"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    return self._send(200, r.read())
            except Exception as e:  # noqa: BLE001
                return self._send(502, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            return self._send(404, {"error": "only /v1/chat/completions is proxied"})
        n = int(self.headers.get("Content-Length", 0))
        try:
            reqbody = json.loads(self.rfile.read(n) or b"{}")
        except Exception:  # noqa: BLE001
            return self._send(400, {"error": "bad json"})
        model = reqbody.get("model", "")
        messages = reqbody.get("messages", [])
        want_stream = bool(reqbody.get("stream"))
        intent = next((msg.get("content", "") for msg in reversed(messages)
                       if msg.get("role") == "user"), "")
        # We must see the whole completion to run the loop, so we always call upstream non-streamed.
        try:
            raw = upstream_chat(model, messages,
                                temperature=reqbody.get("temperature", 0.4),
                                max_tokens=reqbody.get("max_tokens", 1400))
        except Exception as e:  # noqa: BLE001
            return self._send(502, {"error": f"upstream: {e}"})
        try:
            content, note = harden_content(raw, model, intent)
        except Exception as e:  # noqa: BLE001
            content, note = raw, f"secure-proxy: harness error, passthrough ({e})"
        if want_stream:
            return self._send_stream(model, content)
        self._send(200, {
            "id": "secure-proxy", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": content}}],
            "secure_proxy_note": note,
        })

    def _send_stream(self, model, content):
        # Emit the (already-hardened) content as a minimal SSE stream so streaming clients work.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def chunk(delta, finish=None):
            payload = {"id": "secure-proxy", "object": "chat.completion.chunk", "model": model,
                       "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())

        chunk({"role": "assistant"})
        chunk({"content": content})
        chunk({}, finish="stop")
        self.wfile.write(b"data: [DONE]\n\n")


# --------------------------------------------------------------------------- self-test
def self_test():
    INSECURE_GO = 'package main\nimport ("database/sql";"fmt")\nfunc q(db *sql.DB,id string){db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s",id))}\n'
    SECURE_GO = 'package main\nimport "database/sql"\nfunc q(db *sql.DB,id string){db.Query("SELECT * FROM u WHERE id=$1",id)}\n'
    INSECURE_PY = "import yaml\ndef f(s):\n    return yaml.load(s)\n"
    SECURE_PY = "import yaml\ndef f(s):\n    return yaml.safe_load(s)\n"
    # Quarantine controls: safe subprocess (advisory-only, must pass) vs shell=True (real, must block).
    SAFE_SUB = ('import subprocess, re\ndef p(h):\n    if not re.match(r"^[a-zA-Z0-9.-]+$", h):'
                ' raise ValueError()\n    return subprocess.run(["ping","-c","1",h], timeout=5).returncode\n')
    INJECT_SUB = 'import subprocess\ndef p(h):\n    return subprocess.run("ping -c 1 " + h, shell=True)\n'
    ig, sg = assess("go", INSECURE_GO), assess("go", SECURE_GO)
    ip, sp = assess("python", INSECURE_PY), assess("python", SECURE_PY)
    ss, inj = assess("python", SAFE_SUB), assess("python", INJECT_SUB)
    checks = [
        ("go: insecure has findings", len(ig[2]) > 0),
        ("go: secure is clean", len(sg[2]) == 0),
        ("py: insecure has findings", len(ip[2]) > 0),
        ("py: secure is clean", len(sp[2]) == 0),
        ("py: safe subprocess passes (advisories quarantined)", len(ss[2]) == 0),
        ("py: shell=True injection still blocks (TP kept)", len(inj[2]) > 0),
        ("splice targets a fenced block", FENCE.search("x\n```go\n" + SECURE_GO + "```\n") is not None),
        ("extract drops split-fence language tag", not gen.extract_code(
            "```\npython\nimport os\n").startswith("python")),
    ]
    ok = all(p for _d, p in checks)
    for d, p in checks:
        print(f"  [{'PASS' if p else 'FAIL'}] {d}")
    print("secure-proxy self-test:", "PASS" if ok else "FAIL")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=int(os.environ.get("SECURE_PROXY_PORT", "8090")))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        raise SystemExit(0 if self_test() else 1)
    host = os.environ.get("SECURE_PROXY_HOST", "127.0.0.1")
    srv = ThreadingHTTPServer((host, args.port), Handler)
    print(f"secure-proxy on http://{host}:{args.port}/v1  ->  upstream {UPSTREAM}  "
          f"(max_iters={MAX_ITERS})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
