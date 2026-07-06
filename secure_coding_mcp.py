#!/usr/bin/env python3
"""Secure-Coding MCP server — the Phase 3 verify-and-repair harness as callable tools.

This exposes the research finding as a service: generation guided by a secure-coding prompt AND a
generate -> build+scan -> feed-findings-back -> regenerate loop, which reduced vulnerability density
of generated Go by ~98-100% at preserved build robustness (vs a prompt alone, which collapses
buildability). Any MCP client (SemaClaw, Claude Code, Cursor) can call:

  secure_generate(spec)  - write new Go code for a spec, harness-hardened + repair-looped
  harden_code(code)      - take existing code, scan and repair its weaknesses (before/after)
  audit_code(code)       - run the Phase-2 detectors (+ gosec if available); structured findings
  score_code(code)       - security+robustness scorecard for a snippet (build/vet/findings)

Run:  python secure_coding_mcp.py         (stdio transport)
Deps: mcp (FastMCP), pyyaml; a served OpenAI-compatible model (env PHASE3_MODEL_URL/PHASE3_MODEL).
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP  # noqa: E402
import generate as gen  # model_chat, extract_code, repair, build_and_scan  # noqa: E402

SCANNER = HERE / "scan_repo.py"
SECURE_SYS = (HERE / "secure_system_prompt.txt").read_text()
mcp = FastMCP("secure-coding")


def _scan_code(code: str):
    """Run the Phase-2 detectors on a snippet; return structured findings."""
    with tempfile.TemporaryDirectory(prefix="mcp-scan-") as tmp:
        wd = pathlib.Path(tmp)
        (wd / "snippet.go").write_text(code)
        cand = wd / "c.jsonl"
        subprocess.run([sys.executable, str(SCANNER), "--repo", str(wd), "--out", str(cand)],
                       capture_output=True, timeout=60)
        out = []
        if cand.exists():
            for line in cand.read_text().splitlines():
                if line.strip():
                    r = json.loads(line)
                    out.append({"line": r["line"], "severity": r["severity"],
                                "category": r["category"], "cwe": r["cwe"],
                                "detector": r["pattern_id"], "why": r["rationale"]})
        return out


def _metrics(code: str):
    ok, err, findings_text = gen.build_and_scan(code)
    findings = _scan_code(code)
    return {"builds": ok, "build_error": (err[:600] if not ok else ""),
            "findings": findings, "n_findings": len(findings)}


@mcp.tool()
def secure_generate(spec: str, language: str = "go", repair_iters: int = 2) -> dict:
    """Generate secure, robust code for a natural-language spec using the verify-and-repair harness.
    Returns the vetted code plus whether it builds and any residual detector findings."""
    code = gen.extract_code(gen.model_chat(SECURE_SYS, spec))
    code = gen.repair(SECURE_SYS, spec, code, repair_iters)
    m = _metrics(code)
    return {"code": code, **m}


@mcp.tool()
def harden_code(code: str, intent: str = "", repair_iters: int = 2) -> dict:
    """Take EXISTING code and make it secure+robust: scan it, feed the compiler errors and detector
    findings back to the model, and return the hardened code with a before/after comparison."""
    before = _metrics(code)
    task = intent or "Harden this Go code (fix security weaknesses and make it compile) without changing its intended behavior."
    hardened = gen.repair(SECURE_SYS, f"{task}\n\nExisting code:\n```go\n{code}\n```", code, repair_iters)
    after = _metrics(hardened)
    return {"hardened_code": hardened,
            "before": {"builds": before["builds"], "n_findings": before["n_findings"],
                       "findings": before["findings"]},
            "after": {"builds": after["builds"], "n_findings": after["n_findings"],
                      "findings": after["findings"]}}


@mcp.tool()
def audit_code(code: str) -> dict:
    """Audit a code snippet for weak techniques prone to vulnerabilities (Phase-2 detectors, each
    with CWE + rationale). Candidates, not verdicts — verify reachability before acting."""
    findings = _scan_code(code)
    return {"n_findings": len(findings), "findings": findings,
            "note": "Candidates require verification: is the value attacker-controlled and the sink reachable?"}


@mcp.tool()
def score_code(code: str) -> dict:
    """Return a security+robustness scorecard for a Go snippet: does it build, and its findings."""
    return _metrics(code)


if __name__ == "__main__":
    mcp.run()
