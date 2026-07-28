#!/usr/bin/env python3
"""The bootstrap lane: privilege that arrives with the data.

WHY THIS LANE EXISTS
`init-db.sql` was the last file in the subject that no lane read. Reading it turned out to
be an anticlimax -- it is a placeholder that does nothing -- and the search that started
there found the real defect one file over:

    admin = User(username="admin", hashed_password=hash_password("admin123"),
                 role="admin")

Every deployment of this application ships with an administrator whose password is
`admin123`. No vulnerability is required to use it; you log in. It is E5's cousin --
privilege arriving through the seed rather than through an API -- and nothing saw it:
bandit's hardcoded-password rule did not fire (its only hit in this repository is the false
positive on the string "bearer"), the authorization lane reads route handlers, and a
dataflow engine sees a constant reaching a hashing function, which is what a password is
supposed to do.

WHY IT SPANS TWO RUNTIMES
"A bootstrap path creates a privileged account with a literal credential" is true of a SQL
seed script and of a Python one in exactly the same way. The rule is therefore declared
once, in packs/general/security, and BOUND by both language packs -- one id, one weight,
two detectors. That mechanism existed before this lane needed it; this is the first rule
that actually uses it.

THE BALANCE THIS LANE IS BUILT AROUND
A seed script is allowed to do things application code is not. It creates roles, grants
rights, and inserts the first administrator, because without that first account nobody can
log in to create the second one. A lane that forbade any of that would be correct in the
abstract and deleted within a week. So every rule here fires on the part that is NOT
necessary: the credential being a LITERAL rather than an environment value, the grant being
to the RUNTIME role rather than a migration role, the account being left usable rather than
forced to change. Bootstrap is legitimate; shipping the bootstrap secret is not.
"""
import ast
import json
import os
import re
import sys

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}

# Names that mark a row/object as privileged.
PRIV_VALUES = {"admin", "administrator", "superuser", "root", "owner", "superadmin"}
PRIV_FIELDS = {"role", "is_admin", "is_superuser", "is_staff", "permissions", "scopes"}
PASSWORD_FIELDS = {"password", "hashed_password", "password_hash", "passwd", "pwd"}
# Functions that turn a literal into a stored credential.
HASHERS = {"hash_password", "generate_password_hash", "get_password_hash", "make_password",
           "hashpw", "crypt"}

# A file is a bootstrap path if it is named like one or is run by one.
SEED_NAMES = re.compile(r"(seed|init|bootstrap|fixture|demo_data|sample_data)", re.I)


def _files(root, exts):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(exts):
                out.append(os.path.join(dirpath, fn))
    return out


# ---------------------------------------------------------------------------
# Python seed scripts
# ---------------------------------------------------------------------------
def _literal_password(node):
    """A literal password, directly or wrapped in a hashing call. Returns the literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call):
        fn = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if fn in HASHERS:
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    return a.value
    return None


def scan_python(root):
    """Bootstrap findings in Python. Returns (findings, unparsed_or_None)."""
    root = os.path.abspath(root)
    findings = []
    for path in _files(root, (".py",)):
        rel = os.path.relpath(path, root)
        if not SEED_NAMES.search(os.path.basename(rel)):
            continue                      # not a bootstrap path
        try:
            tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
        except SyntaxError:
            return None, rel

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            privileged = False
            for f in PRIV_FIELDS & set(kw):
                v = kw[f]
                if isinstance(v, ast.Constant):
                    if v.value is True or (isinstance(v.value, str)
                                           and v.value.lower() in PRIV_VALUES):
                        privileged = True
            if not privileged:
                continue
            for f in PASSWORD_FIELDS & set(kw):
                lit = _literal_password(kw[f])
                if lit is None:
                    continue
                findings.append({
                    "tool": "seed", "rule": "seed/default-admin-credential",
                    "file": rel, "line": node.lineno, "sev": "HIGH",
                    "message": (f"the bootstrap path creates a privileged account with a "
                                f"literal password ({'*' * len(lit)}, {len(lit)} chars)"),
                    "remedy": ("read the bootstrap password from the environment and refuse "
                               "to seed without it, or create the account disabled and force "
                               "a password set on first use. Seeding the first administrator "
                               "is legitimate; shipping its password is not."),
                })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings, None


# ---------------------------------------------------------------------------
# SQL seed / init scripts
# ---------------------------------------------------------------------------
_GRANT_ALL = re.compile(r"\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+(.+?)\s+TO\s+([^\s;]+)",
                        re.I | re.S)
_SUPERUSER = re.compile(r"\bCREATE\s+(?:ROLE|USER)\s+([^\s;]+)[^;]*?\bSUPERUSER\b", re.I | re.S)
_CREATE_ROLE_PW = re.compile(
    r"\bCREATE\s+(?:ROLE|USER)\s+([^\s;]+)[^;]*?\bPASSWORD\s+'([^']+)'", re.I | re.S)
_INSERT = re.compile(r"\bINSERT\s+INTO\s+([^\s(]+)\s*\(([^)]*)\)\s*VALUES\s*(.+?);",
                     re.I | re.S)


def _line_of(src, idx):
    return src.count("\n", 0, idx) + 1


def scan_sql(path):
    """Bootstrap findings in one .sql file. Returns (findings, unreadable_or_None)."""
    try:
        src = open(path, encoding="utf8", errors="replace").read()
    except OSError:
        return None, path
    name = os.path.basename(path)
    findings = []

    for m in _GRANT_ALL.finditer(src):
        findings.append({
            "tool": "seed", "rule": "sql/grant-all-privileges",
            "file": name, "line": _line_of(src, m.start()), "sev": "MEDIUM",
            "message": (f"GRANT ALL on {m.group(1).strip()[:40]} to "
                        f"{m.group(2).strip()}"),
            "remedy": ("separate the migration role from the runtime role: the migration "
                       "role may hold DDL rights and is used once, the role the application "
                       "connects with should hold SELECT/INSERT/UPDATE/DELETE on its own "
                       "tables and nothing else"),
        })

    for m in _SUPERUSER.finditer(src):
        findings.append({
            "tool": "seed", "rule": "sql/superuser-role",
            "file": name, "line": _line_of(src, m.start()), "sev": "MEDIUM",
            "message": f"role {m.group(1).strip()} is created SUPERUSER",
            "remedy": ("grant the specific rights the role needs; SUPERUSER bypasses row "
                       "level security and every grant you write afterwards"),
        })

    for m in _CREATE_ROLE_PW.finditer(src):
        findings.append({
            "tool": "seed", "rule": "sql/literal-role-password",
            "file": name, "line": _line_of(src, m.start()), "sev": "MEDIUM",
            "message": f"role {m.group(1).strip()} is created with a literal password",
            "remedy": ("supply the password from the environment at provisioning time; a "
                       "literal here is committed, imaged and shipped"),
        })

    for m in _INSERT.finditer(src):
        cols = [c.strip().strip('"').lower() for c in m.group(2).split(",")]
        values = m.group(3)
        priv_col = [i for i, c in enumerate(cols) if c in PRIV_FIELDS]
        pw_col = [i for i, c in enumerate(cols) if c in PASSWORD_FIELDS]
        if not priv_col or not pw_col:
            continue
        for row in re.finditer(r"\(([^)]*)\)", values):
            cells = [c.strip().strip("'\"") for c in row.group(1).split(",")]
            if len(cells) != len(cols):
                continue
            if not any(cells[i].lower() in PRIV_VALUES or cells[i].lower() in ("true", "1")
                       for i in priv_col):
                continue
            # NULL / DEFAULT / empty is exactly the remedy this rule asks for: the account
            # exists so somebody can be granted it, and there is no usable credential to
            # ship. A rule that flagged the fix would never go quiet.
            if all(cells[i].lower() in ("null", "default", "")
                   or cells[i].lower().startswith("current_") or "()" in cells[i]
                   for i in pw_col):
                continue
            findings.append({
                "tool": "seed", "rule": "seed/default-admin-credential",
                "file": name, "line": _line_of(src, m.start()), "sev": "HIGH",
                "message": (f"the seed inserts a privileged row into "
                            f"{m.group(1).strip()} with a literal credential"),
                "remedy": ("insert the bootstrap administrator with no usable credential "
                           "and set it out of band, or take the value from the environment "
                           "at provisioning time"),
            })
    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings, None


def scan_sql_tree(root):
    out = []
    for path in _files(root, (".sql", ".ddl")):
        found, bad = scan_sql(path)
        if found is None:
            return None, bad
        for f in found:
            f["file"] = os.path.relpath(path, root)
        out += found
    return out, None


# ---------------------------------------------------------------------------
POS_PY = '''
from auth import hash_password
from models import User


def seed(db):
    admin = User(username="admin", email="a@example.com",
                 hashed_password=hash_password("admin123"), role="admin")
    db.add(admin)
'''

NEG_PY = '''
import os

from auth import hash_password
from models import User


def seed(db):
    """The bootstrap account is still created -- that is legitimate and necessary -- but
    its password comes from the environment and seeding refuses to proceed without it."""
    pw = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    admin = User(username="admin", email="a@example.com",
                 hashed_password=hash_password(pw), role="admin")
    db.add(admin)

    # An ordinary, unprivileged demo row with a literal password is not this rule's concern:
    # it grants nothing.
    demo = User(username="demo", email="d@example.com",
                hashed_password=hash_password("demo1234"), role="user")
    db.add(demo)
'''

POS_SQL = """
CREATE ROLE app_runtime WITH LOGIN PASSWORD 'app_pass';
CREATE ROLE migrator WITH LOGIN SUPERUSER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_runtime;
INSERT INTO users (username, hashed_password, role) VALUES
  ('admin', '$2b$12$abcdefghijklmnopqrstuv', 'admin');
"""

NEG_SQL = """
-- A migration role with DDL rights, used once, is the RECOMMENDED shape and must be silent.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_runtime;
-- A bootstrap row with no usable credential: the account exists, the password is set out
-- of band. This is the fix the rule asks for.
INSERT INTO users (username, hashed_password, role) VALUES
  ('admin', NULL, 'admin');
-- An unprivileged demo row is not this rule's concern.
INSERT INTO users (username, hashed_password, role) VALUES
  ('demo', 'x', 'user');
"""


def _selftest():
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        pos, neg = os.path.join(td, "pos"), os.path.join(td, "neg")
        os.makedirs(pos)
        os.makedirs(neg)
        open(os.path.join(pos, "seed_data.py"), "w").write(POS_PY)
        open(os.path.join(neg, "seed_data.py"), "w").write(NEG_PY)
        open(os.path.join(pos, "init-db.sql"), "w").write(POS_SQL)
        open(os.path.join(neg, "init-db.sql"), "w").write(NEG_SQL)

        pf, _ = scan_python(pos)
        hit = any(f["rule"] == "seed/default-admin-credential" for f in pf)
        print(("[PASS] " if hit else "[FAIL] ")
              + "positive control (python): a seeded admin with a literal password fires")
        ok = ok and hit

        nf, _ = scan_python(neg)
        clean = not any(f["rule"] == "seed/default-admin-credential" for f in nf)
        print(("[PASS] " if clean else "[FAIL] ") + "negative control (python): a bootstrap "
              "admin whose password comes from the environment is the FIX")
        print(("[PASS] " if clean else "[FAIL] ") + "negative control (python): an "
              "unprivileged demo account with a literal password is not this rule")
        ok = ok and clean

        sf, _ = scan_sql(os.path.join(pos, "init-db.sql"))
        got = {f["rule"] for f in sf}
        for r in ["sql/grant-all-privileges", "sql/superuser-role",
                  "sql/literal-role-password", "seed/default-admin-credential"]:
            h = r in got
            print(("[PASS] " if h else "[FAIL] ") + f"positive control (sql) fires: {r}")
            ok = ok and h

        sn, _ = scan_sql(os.path.join(neg, "init-db.sql"))
        got = {f["rule"] for f in sn}
        for label, r in [("a narrowly-granted runtime role is the recommended shape",
                          "sql/grant-all-privileges"),
                         ("a bootstrap row with NULL credential is the fix",
                          "seed/default-admin-credential")]:
            c = r not in got
            print(("[PASS] " if c else "[FAIL] ") + f"negative control (sql) silent: {label}")
            ok = ok and c

        missing = os.path.join(td, "nope.sql")
        f, bad = scan_sql(missing)
        unm = f is None and bad is not None
        print(("[PASS] " if unm else "[FAIL] ")
              + "an unreadable script returns UNMEASURED, not zero findings")
        ok = ok and unm

        badpy = os.path.join(td, "bad")
        os.makedirs(badpy)
        open(os.path.join(badpy, "seed_x.py"), "w").write("def f(:\n")
        f, where = scan_python(badpy)
        unm2 = f is None and where is not None
        print(("[PASS] " if unm2 else "[FAIL] ")
              + "a seed module that does not parse returns UNMEASURED")
        ok = ok and unm2
    print("\nall seed-lane controls passed" if ok else "\nCONTROLS FAILED")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    target = sys.argv[1]
    py, bad = scan_python(target)
    sq, bad2 = scan_sql_tree(target)
    if py is None or sq is None:
        print(f"UNMEASURED: {bad or bad2}")
        sys.exit(2)
    for f in py + sq:
        print(f"  [{f['sev']:<6}] {f['rule']:<32} {f['file']}:{f['line']} — {f['message']}")
