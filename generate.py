#!/usr/bin/env python3
"""Generate code for each benchmark task under each condition, for one served model.

Conditions:
  baseline       - neutral "write Go that does X" system prompt (no security guidance)
  guided         - the secure_system_prompt.txt harness injected as the system prompt
  guided_repair  - guided, then a scan-repair loop: build the result + scan it, and if it fails
                   to compile or trips a detector, feed that back and regenerate (up to N iters).
                   This is the harness as a FEEDBACK LOOP, not just a better prompt.

Output: out/<model_tag>/<condition>/<task_id>[_<sample>].go
Stdlib + yaml only; talks to an OpenAI-compatible endpoint (default: local DiffusionGemma).
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SCANNER = HERE / "scan_repo.py"
BASE_URL = os.environ.get("SECURE_HARNESS_MODEL_URL") or os.environ.get("PHASE3_MODEL_URL", "http://localhost:8080/v1")
MODEL = os.environ.get("SECURE_HARNESS_MODEL") or os.environ.get("PHASE3_MODEL", "")
KEY = os.environ.get("SECURE_HARNESS_KEY") or os.environ.get("PHASE3_KEY", "dummy")

BASELINE_SYS = ("You are a Go engineer. Implement exactly what is asked. "
                "Output only Go code in one ```go block, no prose.")


def model_chat(system, user, max_tokens=1200, temperature=0.4):
    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens, "temperature": temperature,
        "chat_template_kwargs": {"enable_thinking": False},
    }).encode()
    req = urllib.request.Request(f"{BASE_URL}/chat/completions", data=body,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {KEY}"}, method="POST")
    # Retry transient failures with backoff. A failed generation would otherwise be recorded as a
    # clean (0-finding) sample, biasing security scores upward — so absorb blips, re-raise real ones.
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            msg = d["choices"][0]["message"]
            return msg.get("content") or msg.get("reasoning") or ""
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < 3:
                time.sleep(2 ** attempt)  # 1s, 2s, 4s
    raise last


def extract_code(text):
    m = re.search(r"```(?:go|golang)?[^\n]*\n(.*?)```", text, re.DOTALL)
    code = m.group(1) if m else text
    lines = [ln for ln in code.splitlines() if ln.strip() not in ("```", "```go", "```golang")]
    if lines and lines[0].strip().lower() in ("go", "golang"):
        lines = lines[1:]
    return "\n".join(lines).strip() + "\n"


def _lib(code):
    if re.search(r"^\s*package\s+\w+", code, re.MULTILINE):
        return re.sub(r"^[ \t]*package\s+\w+", "package p", code, count=1, flags=re.MULTILINE)
    return "package p\n\n" + code


HARNESS_MOD = HERE / ".harness-mod"  # pre-warmed module so the build check can compile x/crypto
                                     # (bcrypt/argon2/scrypt) — the secure choice for password hashing


def _ensure_deps():
    """One-time warm of a module dir carrying common secure-crypto deps (golang.org/x/crypto), so the
    build check can compile best-practice code instead of failing the secure choice. Cached in a
    persistent module cache; needs network only on the first call. Returns True if go.mod+go.sum ready."""
    if (HARNESS_MOD / "go.sum").exists():
        return True
    env = {**os.environ, "GOTOOLCHAIN": "local"}
    try:
        HARNESS_MOD.mkdir(exist_ok=True)
        if not (HARNESS_MOD / "go.mod").exists():
            subprocess.run(["go", "mod", "init", "harnessdeps"], cwd=HARNESS_MOD,
                           capture_output=True, timeout=60, env=env)
            (HARNESS_MOD / "deps.go").write_text('package harnessdeps\n'
                                                 'import _ "golang.org/x/crypto/bcrypt"\n')
        subprocess.run(["go", "get", "golang.org/x/crypto/bcrypt@latest"], cwd=HARNESS_MOD,
                       capture_output=True, timeout=180, env=env)
        return (HARNESS_MOD / "go.sum").exists()
    except Exception:  # noqa: BLE001
        return False


def build_and_scan(code):
    """Return (build_ok, build_err, findings_text). Used to drive the repair loop."""
    build_ok, build_err, findings = True, "", ""
    with tempfile.TemporaryDirectory(prefix="p3gen-") as tmp:
        wd = pathlib.Path(tmp)
        if _ensure_deps() and (HARNESS_MOD / "go.sum").exists():
            shutil.copyfile(HARNESS_MOD / "go.mod", wd / "go.mod")   # brings x/crypto into scope
            shutil.copyfile(HARNESS_MOD / "go.sum", wd / "go.sum")
        else:
            (wd / "go.mod").write_text("module gentmp\n\ngo 1.24\n")  # fallback: stdlib-only
        (wd / "code.go").write_text(_lib(code))
        try:
            r = subprocess.run(["go", "build", "./..."], cwd=wd, capture_output=True,
                               encoding="utf-8", errors="replace", timeout=90)
            build_ok, build_err = r.returncode == 0, r.stderr.strip()
        except Exception as e:  # noqa: BLE001
            build_ok, build_err = False, str(e)
        cand = wd / "c.jsonl"
        try:
            subprocess.run([sys.executable, str(SCANNER), "--repo", str(wd),
                            "--out", str(cand)], cwd=wd, capture_output=True, timeout=60)
            if cand.exists():
                hits = [json.loads(l) for l in cand.read_text().splitlines() if l.strip()]
                findings = "; ".join(f"{h['severity']} {h['pattern_id']} (line {h['line']}): "
                                     f"{h['rationale']}" for h in hits)
        except Exception:  # noqa: BLE001
            pass
    return build_ok, build_err, findings


def repair(system, task_prompt, code, iters):
    """Feed build errors + detector findings back and regenerate, up to `iters` passes."""
    for _ in range(iters):
        ok, berr, findings = build_and_scan(code)
        if ok and not findings:
            break
        problems = []
        if not ok:
            problems.append(f"It does not compile:\n{berr}")
        if findings:
            problems.append(f"A security scanner flagged:\n{findings}")
        fix_user = (f"{task_prompt}\n\nYour previous solution had problems:\n"
                    + "\n".join(problems)
                    + "\n\nReturn a corrected version that compiles cleanly and resolves every "
                    "issue. Output only Go code in one ```go block.")
        code = extract_code(model_chat(system, fix_user, temperature=0.2))
    return code


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tasks", default=str(HERE / "tasks.yaml"))
    ap.add_argument("--conditions", default="baseline,guided,guided_repair")
    ap.add_argument("--model-tag", default=None)
    ap.add_argument("--out", default=str(HERE / "out"))
    ap.add_argument("--samples-per-task", type=int, default=1)
    ap.add_argument("--temperature", type=float, default=0.4)
    ap.add_argument("--repair-iters", type=int, default=1)
    args = ap.parse_args()

    import yaml
    tasks = yaml.safe_load(pathlib.Path(args.tasks).read_text())["tasks"]
    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    guided_sys = (HERE / "secure_system_prompt.txt").read_text()
    tag = args.model_tag or re.sub(r"[^A-Za-z0-9]+", "-", MODEL)[:24]
    K = args.samples_per_task

    print(f"model={MODEL} tag={tag} conditions={conditions} tasks={len(tasks)} K={K}")
    for cond in conditions:
        sysprompt = BASELINE_SYS if cond == "baseline" else guided_sys
        outdir = pathlib.Path(args.out) / tag / cond
        outdir.mkdir(parents=True, exist_ok=True)
        for t in tasks:
            for i in range(K):
                try:
                    code = extract_code(model_chat(sysprompt, t["prompt"],
                                                   temperature=args.temperature))
                    if cond == "guided_repair":
                        code = repair(sysprompt, t["prompt"], code, args.repair_iters)
                except Exception as e:  # noqa: BLE001
                    code = f"// generation error: {e}\n"
                name = f"{t['id']}.go" if K == 1 else f"{t['id']}_{i}.go"
                (outdir / name).write_text(code)
            print(f"  [{cond}] {t['id']}: {K} sample(s)", flush=True)
    print(f"done -> {pathlib.Path(args.out) / tag}")


if __name__ == "__main__":
    main()
