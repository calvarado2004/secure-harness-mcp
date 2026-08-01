#!/usr/bin/env python3
"""The functional oracle for the chess platform: drive the real workflow over HTTP.

WHY THIS EXISTS
The no-harm gate protects working endpoints, so a subject with no functional oracle has no
usable gate: every candidate dominates a state that was never measured, and the clause that
makes this harness non-regressing quietly does nothing. Study 3 had a security axis and
nothing else, which means the pipeline could not have been run on it at all.

WHAT IT SCORES, AND AGAINST WHAT
Each endpoint is scored against the response a correct implementation would give, not the
mere absence of an error. A correct refusal PASSES: asking for another user's private data
and receiving 401 or 403 is the endpoint working, and an oracle that rewards 200 everywhere
teaches a model to remove its own guards. That is not hypothetical in this project's history,
which is why the rule is stated here rather than assumed.

THE MEASURABILITY COORDINATE
`measured` is false when the probe could not exercise the surface at all: the stack is not up,
the API never answered, registration failed so nothing downstream could be attempted. A run
that scores zero working because nothing was running must not be mistaken for a run that
scores zero because everything broke, since every later state dominates a false floor.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("CHESS_API", "http://127.0.0.1:3002")
TIMEOUT = 15


def _req(method, path, body=None, token=None, expect_json=True):
    url = BASE.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read().decode("utf8", "replace")
            return r.status, (json.loads(raw) if expect_json and raw else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf8", "replace")
        try:
            return e.code, json.loads(raw) if raw else None
        except ValueError:
            return e.code, raw
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return None, str(e)


def _wait_for_api(seconds=90):
    """A stack that has not finished starting is not a broken application."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        st, _ = _req("GET", "/health")
        if st == 200:
            return True
        time.sleep(2)
    return False


def probe(base=None):
    """Drive the workflow. Returns the harness's usual functional verdict shape."""
    global BASE
    if base:
        BASE = base
    verdicts, evidence = {}, {}

    def score(name, ok, detail=""):
        verdicts[name] = "OK" if ok else "FAIL"
        if detail:
            evidence[name] = detail
        return ok

    if not _wait_for_api():
        return {"started": False, "measured": False, "working": 0, "tested": 0,
                "verdicts": {}, "why": "the API never answered /health"}

    stamp = str(int(time.time() * 1000))[-9:]
    u1 = {"username": f"probe{stamp}", "email": f"probe{stamp}@example.invalid",
          "password": "Str0ng!Passw0rd-2026", "displayName": "Probe One"}
    u2 = {"username": f"other{stamp}", "email": f"other{stamp}@example.invalid",
          "password": "Str0ng!Passw0rd-2026", "displayName": "Probe Two"}

    st, _ = _req("GET", "/health")
    score("/health", st == 200, f"status {st}")

    st, body = _req("POST", "/api/auth/register", u1)
    score("/api/auth/register", st == 201 and isinstance(body, dict), f"status {st}")
    tok = (body or {}).get("accessToken") if isinstance(body, dict) else None

    st2, body2 = _req("POST", "/api/auth/register", u2)
    tok2 = (body2 or {}).get("accessToken") if isinstance(body2, dict) else None
    id2 = ((body2 or {}).get("user") or {}).get("id") if isinstance(body2, dict) else None

    st, body = _req("POST", "/api/auth/login",
                    {"username": u1["username"], "password": u1["password"]})
    ok = st == 200 and isinstance(body, dict) and bool(body.get("accessToken"))
    score("/api/auth/login", ok, f"status {st}")
    if ok:
        tok = body["accessToken"]
        refresh = body.get("refreshToken")
    else:
        refresh = None

    # A wrong password must be REFUSED. An endpoint that accepts anything is not working.
    st, _ = _req("POST", "/api/auth/login",
                 {"username": u1["username"], "password": "wrong-password-entirely"})
    score("/api/auth/login (refuses bad password)", st in (400, 401),
          f"status {st}; a 2xx here would mean authentication does nothing")

    if refresh:
        st, body = _req("POST", "/api/auth/refresh", {"refreshToken": refresh})
        score("/api/auth/refresh", st == 200 and isinstance(body, dict)
              and bool(body.get("accessToken")), f"status {st}")

    st, body = _req("GET", "/api/users/me", token=tok)
    score("/api/users/me", st == 200 and isinstance(body, dict)
          and body.get("username") == u1["username"], f"status {st}")

    # ... and it must REFUSE an anonymous caller.
    st, _ = _req("GET", "/api/users/me")
    score("/api/users/me (refuses anonymous)", st in (401, 403), f"status {st}")

    st, _ = _req("GET", "/api/users/me/elo", token=tok)
    score("/api/users/me/elo", st == 200, f"status {st}")

    st, _ = _req("GET", "/api/users/me/history", token=tok)
    score("/api/users/me/history", st == 200, f"status {st}")

    st, _ = _req("PATCH", "/api/users/me", {"displayName": "Renamed"}, token=tok)
    score("/api/users/me (update)", st in (200, 204), f"status {st}")

    if id2:
        st, body = _req("GET", f"/api/users/{id2}", token=tok)
        leaked = isinstance(body, dict) and any(
            k in body for k in ("email", "password", "password_hash", "refresh_token"))
        score("/api/users/<id> (public projection)", st == 200 and not leaked,
              f"status {st}" + ("; response carried a private field" if leaked else ""))

    st, _ = _req("GET", "/api/theory/categories")
    score("/api/theory/categories", st == 200, f"status {st}")

    st, _ = _req("GET", "/api/theory/lessons")
    score("/api/theory/lessons", st == 200, f"status {st}")

    st, _ = _req("GET", "/api/theory/progress", token=tok)
    score("/api/theory/progress", st == 200, f"status {st}")

    st, _ = _req("GET", "/api/theory/progress")
    score("/api/theory/progress (refuses anonymous)", st in (401, 403), f"status {st}")

    # Logout takes the refresh token in the body, because revoking a session means revoking
    # THAT token rather than merely dropping the access one. Sending an empty body scored a
    # 500 and charged the application for it; the endpoint was working and the probe was
    # wrong. Reproduce a failure before believing it.
    st, _ = _req("POST", "/api/auth/logout", {"refreshToken": refresh or ""}, token=tok)
    score("/api/auth/logout", st in (200, 204), f"status {st}")

    working = sum(1 for v in verdicts.values() if v == "OK")
    return {"started": True, "measured": True, "working": working,
            "tested": len(verdicts), "verdicts": verdicts, "evidence": evidence}


if __name__ == "__main__":
    r = probe(sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps(r, indent=1))
    if not r.get("measured"):
        print(f"\nUNMEASURED: {r.get('why')}", file=sys.stderr)
        sys.exit(2)
    print(f"\nworking {r['working']}/{r['tested']}")
    for k, v in r["verdicts"].items():
        if v != "OK":
            print(f"  FAIL {k}: {r.get('evidence', {}).get(k, '')}")
