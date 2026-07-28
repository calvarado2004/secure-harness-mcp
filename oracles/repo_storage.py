#!/usr/bin/env python3
"""Object-storage lane: what the bucket policy actually grants.

WHY THIS LANE EXISTS
The subject uploads vehicle photographs to MinIO and, on first run, sets a bucket policy:

    "Principal": {"AWS": "*"}, "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::<bucket>/*"]

Every object in the bucket, for ever, readable by anyone -- and the wildcard is on the
BUCKET, not on the `vehicles/` prefix the application actually publishes. Nothing in that
code is a dangerous call. bandit has no pattern for it, CodeQL has no sink, the
authorization lane reads handlers and this is a helper, and the nginx lane sees a proxy
route that is doing what it was told. The grant is data -- a JSON document built in a
dictionary literal -- and reading it is the only way to know what the system gives away.

That is the same argument every custom lane in this project makes: the interesting
questions are about intent expressed as configuration, and generic engines are built to
find dangerous constructs.

WHAT IT DELIBERATELY DOES NOT DO
It does not connect to anything. It reads the policy the code WOULD set; if the bucket's
live policy was changed by hand afterwards, this lane is describing the source and not the
system, and it says so rather than claiming to have checked the deployment.
"""
import ast
import json
import os
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}

# SDK constructors whose `secure=False` means plaintext HTTP to the object store.
_CLIENTS = {"Minio", "client", "resource"}


def _py_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def _literal(node):
    """Best-effort constant folding of a dict/list/str literal, f-strings included."""
    try:
        return ast.literal_eval(node)
    except Exception:
        pass
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            else:
                parts.append("*")        # an interpolated bucket/prefix name
        return "".join(parts)
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            kk = _literal(k) if k is not None else None
            out[kk if isinstance(kk, str) else str(kk)] = _literal(v)
        return out
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_literal(e) for e in node.elts]
    return None


def _statements(policy):
    if not isinstance(policy, dict):
        return []
    st = policy.get("Statement")
    if isinstance(st, dict):
        return [st]
    return st if isinstance(st, list) else []


def _is_wildcard_principal(p):
    if p == "*":
        return True
    if isinstance(p, dict):
        vals = []
        for v in p.values():
            vals += v if isinstance(v, list) else [v]
        return "*" in vals
    if isinstance(p, list):
        return "*" in p
    return False


def scan_storage(root):
    """Findings for object-storage configuration. Returns (findings, unparsed_or_None)."""
    root = os.path.abspath(root)
    findings = []
    for path in _py_files(root):
        rel = os.path.relpath(path, root)
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None, rel          # unparseable: no answer, not "no findings"

        # --- anonymous grants in a bucket policy ---------------------------
        # The policy is DATA, and it reaches the SDK through whatever plumbing the author
        # chose -- `set_bucket_policy(b, str(policy).replace("'", \'"\'))` in this subject,
        # `json.dumps(p)` elsewhere. Chasing the argument expression means re-implementing
        # constant folding badly, so the lane does the honest thing instead: if the module
        # sets a bucket policy at all, every policy document literal in it is read. A
        # module that builds a policy and never applies it is not reported.
        sets_policy = any(
            isinstance(n, ast.Call)
            and (getattr(n.func, "id", None) or getattr(n.func, "attr", None))
            in ("set_bucket_policy", "put_bucket_policy")
            for n in ast.walk(tree))
        if sets_policy:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                doc = _literal(node)
                if not isinstance(doc, dict) or "Statement" not in doc:
                    continue
                for st in _statements(doc):
                    if not isinstance(st, dict) or st.get("Effect") != "Allow":
                        continue
                    if not _is_wildcard_principal(st.get("Principal")):
                        continue
                    actions = st.get("Action")
                    actions = actions if isinstance(actions, list) else [actions]
                    writes = [a for a in actions if isinstance(a, str)
                              and any(w in a for w in ("Put", "Delete", "*"))]
                    res = st.get("Resource")
                    res = res if isinstance(res, list) else [res]
                    bucket_wide = False
                    for r in res:
                        if not isinstance(r, str) or ":::" not in r:
                            continue
                        tail = r.split(":::", 1)[1]
                        # "<bucket>/*" is the whole bucket; "<bucket>/<prefix>/*" is scoped
                        if tail.endswith("/*") and tail.count("/") == 1:
                            bucket_wide = True
                    # A prefix-scoped, read-only anonymous grant is exactly what the
                    # remedy below asks for. Reporting it anyway would mean the lane never
                    # goes quiet no matter what the model does -- a rule you cannot satisfy
                    # is a rule that gets switched off, and it would have taught the model
                    # that the fix does not work.
                    if not writes and not bucket_wide:
                        continue
                    findings.append({
                        "tool": "storage",
                        "rule": ("storage/anonymous-write" if writes
                                 else "storage/public-read-bucket"),
                        "file": rel, "line": node.lineno,
                        "sev": "HIGH" if writes else "MEDIUM",
                        "message": (
                            f"bucket policy grants {', '.join(str(a) for a in actions)} to "
                            f"Principal '*'"
                            + (" across the WHOLE bucket rather than a published prefix"
                               if bucket_wide else "")),
                        "remedy": (
                            "scope the grant to the prefix that is genuinely public "
                            "(arn:aws:s3:::<bucket>/vehicles/*), keep every other prefix "
                            "private, and never grant Put/Delete to an anonymous "
                            "principal; serve non-public objects through the application "
                            "or with pre-signed URLs"),
                    })

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)

            # --- plaintext transport to the object store -------------------
            if fname in _CLIENTS:
                for kw in node.keywords:
                    if kw.arg in ("secure", "use_ssl", "verify") and \
                            isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append({
                            "tool": "storage", "rule": "storage/plaintext-transport",
                            "file": rel, "line": node.lineno, "sev": "MEDIUM",
                            "message": (f"object-store client constructed with "
                                        f"{kw.arg}=False: credentials and objects cross "
                                        f"the network in clear text"),
                            "remedy": ("enable TLS to the object store, or confirm the "
                                       "hop never leaves an isolated network -- and record "
                                       "that in the project's deployment facts so the "
                                       "claim is checkable rather than assumed"),
                        })
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings, None


# ---------------------------------------------------------------------------
POS = '''
from minio import Minio


def get_client():
    return Minio("minio:9000", access_key="k", secret_key="s", secure=False)


def ensure_bucket(c, bucket):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    c.set_bucket_policy(bucket, str(policy).replace("'", '"'))
'''

NEG = '''
from minio import Minio


def get_client():
    """TLS on: not a transport finding."""
    return Minio("objects.example.com", access_key="k", secret_key="s", secure=True)


def ensure_bucket(c, bucket):
    """A grant scoped to the prefix that is genuinely public, read-only, is the FIX."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::media/vehicles/*"],
            }
        ],
    }
    c.set_bucket_policy(bucket, policy)


def private_bucket(c, bucket):
    """A policy with a named principal is not an anonymous grant."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::media/*"],
            }
        ],
    }
    c.set_bucket_policy(bucket, policy)
'''


def _selftest():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        pos, neg = os.path.join(td, "pos"), os.path.join(td, "neg")
        os.makedirs(pos)
        os.makedirs(neg)
        open(os.path.join(pos, "storage.py"), "w").write(POS)
        open(os.path.join(neg, "storage.py"), "w").write(NEG)

        pf, _ = scan_storage(pos)
        got = {f["rule"] for f in pf}
        for r in ["storage/public-read-bucket", "storage/plaintext-transport"]:
            hit = r in got
            print(("[PASS] " if hit else "[FAIL] ") + f"positive control fires: {r}")
            ok = ok and hit
        wide = any("WHOLE bucket" in f["message"] for f in pf)
        print(("[PASS] " if wide else "[FAIL] ")
              + "positive control: the bucket-wide wildcard is called out, not just the grant")
        ok = ok and wide

        nf, _ = scan_storage(neg)
        got = {f["rule"] for f in nf}
        for label, r in [("secure=True is not a transport finding",
                          "storage/plaintext-transport"),
                         ("a prefix-scoped read-only public grant is the FIX, not a finding",
                          "storage/public-read-bucket")]:
            clean = r not in got
            print(("[PASS] " if clean else "[FAIL] ") + f"negative control silent: {label}")
            ok = ok and clean
        anon = "storage/anonymous-write" not in got
        print(("[PASS] " if anon else "[FAIL] ")
              + "negative control silent: a NAMED principal with write is not anonymous write")
        ok = ok and anon

        bad = os.path.join(td, "bad")
        os.makedirs(bad)
        open(os.path.join(bad, "x.py"), "w").write("def f(:\n")
        f, where = scan_storage(bad)
        unm = f is None and where is not None
        print(("[PASS] " if unm else "[FAIL] ")
              + "a file that does not parse returns UNMEASURED, not zero findings")
        ok = ok and unm
    print("\nall storage-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    found, bad = scan_storage(sys.argv[1])
    if found is None:
        print(f"UNMEASURED: {bad} does not parse")
        sys.exit(2)
    for f in found:
        print(f"  [{f['sev']:<6}] {f['rule']:<30} {f['file']}:{f['line']} — {f['message']}")
