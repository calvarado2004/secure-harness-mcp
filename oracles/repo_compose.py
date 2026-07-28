#!/usr/bin/env python3
"""The compose lane: what the deployment actually publishes, versus what it claims.

WHY THIS LANE EXISTS, AND IT IS PERSONAL
`packs/container/pack.yaml` carried this warning from the day it was written:

    deployment context "must not become a way to talk a finding down. A finding excused
    because we run in a container is only fine if a container lane actually verified the
    container. Otherwise the context is an assertion, not a control."

Then this project's own profile for the brownfield subject asserted `network: internal,
published: [nginx]` -- copied from a different subject, never checked -- while the
repository's compose file published postgres 5432, minio 9000/9001 and the API 8000
straight to the host. A severity downgrade rode on that false claim until an external agent
checked it. Nothing here could have caught it, because nothing here read compose.

This lane is that missing control. It reads the published surface out of the compose file
and compares it with what the project declared, so `deployment.verified` becomes something
a repository EARNS rather than something a YAML file says about itself.

WHAT IT DELIBERATELY DOES NOT DO
It reads one compose file. It does not resolve `extends`, multiple `-f` overlays, profiles,
or `.env` interpolation beyond recording that a value was interpolated. A deployment
assembled from overlays is only partly described here, and the lane reports what it read
rather than implying it read everything.
"""
import json
import os
import re
import sys

# Credentials that ship as documented defaults with the image. Real, and expected in a dev
# stack -- so they are reported at LOW rather than buried among the ones that matter.
KNOWN_DEFAULTS = {
    ("minio_root_user", "minioadmin"), ("minio_root_password", "minioadmin"),
    ("postgres_user", "postgres"), ("postgres_password", "postgres"),
    ("mysql_root_password", "root"),
}
SECRETISH = ("secret", "password", "token", "api_key", "apikey", "private_key", "root_user")


def _load(path):
    try:
        import yaml
        with open(path, encoding="utf8") as f:
            return yaml.safe_load(f), None
    except ImportError:
        return None, "PyYAML is not installed, so the compose file could not be read"
    except Exception as e:
        return None, f"{os.path.basename(path)} could not be parsed: {e}"


def _ports(svc):
    """Host ports this service publishes. `expose` is NOT published; only `ports` is."""
    out = []
    for p in (svc.get("ports") or []):
        if isinstance(p, dict):
            if p.get("published") is not None:
                out.append(str(p["published"]))
            continue
        s = str(p)
        # "127.0.0.1:5432:5432" | "5432:5432" | "5432"
        parts = s.split(":")
        if len(parts) == 3:
            out.append(f"{parts[0]}:{parts[1]}")
        elif len(parts) == 2:
            out.append(parts[0])
        else:
            out.append(parts[0])
    return out


def published_services(compose):
    """{service: [host ports]} for every service reachable from the host."""
    out = {}
    for name, svc in (compose.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        ports = _ports(svc)
        if ports:
            out[name] = ports
    return out


def verify_deployment(path, declared_published):
    """Does the compose file support the project's `deployment.published` claim?

    Returns (ok, detail). This is what `deployment.verified` should be set from -- by
    evidence, not by assertion.
    """
    compose, err = _load(path)
    if compose is None:
        return None, err
    actual = set(published_services(compose))
    declared = set(declared_published or [])
    extra = sorted(actual - declared)
    missing = sorted(declared - actual)
    if not extra and not missing:
        return True, f"compose publishes exactly {sorted(actual)}"
    return False, (f"compose publishes {sorted(actual)}; the project declares "
                   f"{sorted(declared)}"
                   + (f"; UNDECLARED: {extra}" if extra else "")
                   + (f"; declared but not published: {missing}" if missing else ""))


def scan_compose(path, declared_published=None):
    """Findings for one compose file. Returns (findings, unreadable_reason_or_None)."""
    compose, err = _load(path)
    if compose is None:
        return None, err

    src = open(path, encoding="utf8", errors="replace").read()

    def line_of(needle):
        for i, ln in enumerate(src.splitlines(), 1):
            if needle in ln:
                return i
        return 1

    findings = []
    pub = published_services(compose)

    for name, ports in sorted(pub.items()):
        loopback = all(":" in p and p.split(":")[0] in ("127.0.0.1", "localhost")
                       for p in ports)
        if declared_published is not None and name not in set(declared_published) \
                and not loopback:
            findings.append({
                "tool": "compose", "rule": "container/undeclared-published-port",
                "file": os.path.basename(path), "line": line_of(f"{name}:"),
                "sev": "MEDIUM",
                "message": (f"service `{name}` publishes {ports} to the host, and the "
                            f"project's deployment facts do not list it as published"),
                "remedy": ("remove the host port mapping so the service is reachable only "
                           "on the compose network, bind it to 127.0.0.1 for local access, "
                           "or -- if it really is meant to be published -- add it to the "
                           "project's `deployment.published` so the claim matches reality "
                           "and any severity priced against it is honest"),
            })

    for name, svc in sorted((compose.get("services") or {}).items()):
        if not isinstance(svc, dict):
            continue
        env = svc.get("environment") or {}
        if isinstance(env, list):
            env = dict(e.split("=", 1) for e in env if isinstance(e, str) and "=" in e)
        for k, v in env.items():
            key, val = str(k).lower(), str(v)
            if not any(s in key for s in SECRETISH):
                continue
            if "${" in val:                      # taken from the environment: the fix
                continue
            known = (key, val.lower()) in KNOWN_DEFAULTS
            findings.append({
                "tool": "compose", "rule": "container/shipped-service-credential",
                "file": os.path.basename(path), "line": line_of(f"{k}:"),
                "sev": "LOW" if known else "MEDIUM",
                "message": (f"service `{name}` sets {k} to a literal"
                            + (" that is this image's documented default"
                               if known else "")),
                "remedy": ("take the value from the environment (${VAR:?required}) so a "
                           "deployment cannot inherit it silently"
                           + ("; the image default is expected in a dev stack, and it is "
                              "reported so that publishing the service is a visible "
                              "decision rather than an accident" if known else "")),
            })

    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings, None


def scan_tree(root, declared_published=None):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in {"__pycache__", ".git", "node_modules", ".venv"}]
        for fn in sorted(filenames):
            if fn not in ("docker-compose.yml", "docker-compose.yaml", "compose.yml",
                          "compose.yaml"):
                continue
            found, err = scan_compose(os.path.join(dirpath, fn), declared_published)
            if found is None:
                return None, err
            for f in found:
                f["file"] = os.path.relpath(os.path.join(dirpath, fn), root)
            out += found
    return out, None


# ---------------------------------------------------------------------------
POS = """
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: dealership_pass
    ports:
      - "5432:5432"
  minio:
    image: minio/minio:latest
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"
  nginx:
    image: nginx:alpine
    ports:
      - "8080:80"
"""

NEG = """
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?required}
    expose:
      - "5432"
  minio:
    image: minio/minio:latest
    environment:
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:?required}
    ports:
      - "127.0.0.1:9000:9000"
  nginx:
    image: nginx:alpine
    ports:
      - "8080:80"
"""


def _selftest():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        pos = os.path.join(td, "pos.yml")
        neg = os.path.join(td, "neg.yml")
        open(pos, "w").write(POS)
        open(neg, "w").write(NEG)

        pf, err = scan_compose(pos, declared_published=["nginx"])
        if pf is None:
            print(f"[SKIP] compose lane cannot run here: {err}")
            return True
        got = {f["rule"] for f in pf}
        for r in ["container/undeclared-published-port",
                  "container/shipped-service-credential"]:
            hit = r in got
            print(("[PASS] " if hit else "[FAIL] ") + f"positive control fires: {r}")
            ok = ok and hit
        n = len([f for f in pf if f["rule"] == "container/undeclared-published-port"])
        two = n == 2
        print(("[PASS] " if two else "[FAIL] ")
              + f"positive control: both undeclared services reported, nginx not (got {n})")
        ok = ok and two

        nf, _ = scan_compose(neg, declared_published=["nginx"])
        got = {f["rule"] for f in nf}
        clean = "container/undeclared-published-port" not in got
        print(("[PASS] " if clean else "[FAIL] ") + "negative control silent: `expose` is "
              "not publishing, and a 127.0.0.1 binding is not host-reachable")
        ok = ok and clean
        clean2 = "container/shipped-service-credential" not in got
        print(("[PASS] " if clean2 else "[FAIL] ") + "negative control silent: a value "
              "taken from ${ENV} is the fix, not a finding")
        ok = ok and clean2

        # verification, both directions
        v_false, detail = verify_deployment(pos, ["nginx"])
        v_true, _ = verify_deployment(pos, ["nginx", "postgres", "minio"])
        print(("[PASS] " if v_false is False else "[FAIL] ")
              + f"a FALSE `published` claim is refused: {detail[:70]}")
        print(("[PASS] " if v_true is True else "[FAIL] ")
              + "a claim matching the compose file verifies")
        ok = ok and v_false is False and v_true is True

        broken = os.path.join(td, "broken.yml")
        open(broken, "w").write("services: [oops\n")
        f, err = scan_compose(broken)
        unm = f is None and err
        print(("[PASS] " if unm else "[FAIL] ")
              + "an unparseable compose file returns UNMEASURED, not zero findings")
        ok = ok and bool(unm)
    print("\nall compose-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    target = sys.argv[1]
    declared = sys.argv[2].split(",") if len(sys.argv) > 2 else None
    found, err = (scan_tree(target, declared) if os.path.isdir(target)
                  else scan_compose(target, declared))
    if found is None:
        print(f"UNMEASURED: {err}")
        sys.exit(2)
    for f in found:
        print(f"  [{f['sev']:<6}] {f['rule']:<36} {f['file']}:{f['line']} — {f['message']}")
