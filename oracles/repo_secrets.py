#!/usr/bin/env python3
"""A lane for the file type no runtime claims.

WHY THIS EXISTS
Every lane in this harness is organised by execution environment, because that is what
decides which engine can open a file. It works, and it has one structural consequence: a
file that executes in no environment is claimed by nobody. `.env` is exactly that. It is not
Python, not JavaScript, not SQL, not a container manifest. It is configuration, it is read at
startup by whatever language happens to be running, and until now it fell into the
inventory's unclaimed pile.

That pile is reported rather than skipped, which is the only reason this defect was ever
seen. Pointed at a multiplayer chess platform of some two thousand files across four
runtimes, the harness found nothing on everything it could read and listed `backend/.env`
among the files nothing claimed. The file was tracked in git, in a public repository, and
carried the JWT signing key the application authenticates every request with.

WHAT THE RULE IS CAREFUL ABOUT
A committed template is the fix, not the defect. `.env.example` exists so that the KEYS can
be committed without the VALUES, and a lane that flagged it would be telling a project to
delete its own documentation. So three conditions must hold together: the file is tracked by
version control, it is not a template by name, and at least one of its values is a real
secret rather than a placeholder. Any one of the three alone is ordinary.
"""
import os
import re
import subprocess
import sys

# Files that carry configuration values rather than code.
ENV_NAMES = re.compile(r"^\.env(\..+)?$|^.*\.envrc$|^env\.sh$", re.I)
# ... and the ones that exist to be committed.
TEMPLATE = re.compile(r"\.(example|sample|template|dist|default)$|^\.env\.example", re.I)
# Keys whose value is a credential.
SECRET_KEY = re.compile(
    r"(SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|"
    r"CREDENTIAL|DATABASE_URL|DB_URL|CONNECTION_STRING|DSN|SIGNING)", re.I)
# Values that are documentation rather than secrets.
PLACEHOLDER = re.compile(
    r"^(|<.*>|\{\{.*\}\}|\$\{.*\}|change[-_ ]?me|changeme|placeholder|example|your[-_ ].*|"
    r"xxx+|todo|tbd|dummy|fake|sample|secret[-_ ]?here|replace[-_ ]?me|none|null)$", re.I)
PLACEHOLDER_SUBSTR = re.compile(
    r"change[-_ ]?me|placeholder|your[-_ ]|secret[-_ ]here|replace[-_ ]?me|xxxx|todo", re.I)

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}


def _would_be_committed(root, rel):
    """Is anything stopping this credential file from reaching the repository?

    The question is deliberately NOT "is it tracked right now". Tracking is a fact about
    whichever git repository happens to enclose the copy being scanned, and that differs
    between a developer's checkout, an installed copy under a package prefix, and a tarball
    a reviewer unpacked. A lane whose verdict changes with the packaging is not measuring
    the program.

    What does not change is intent. A `.gitignore` that covers the file is a project saying
    it must never be committed, and that is the case this rule has no business in. Anything
    else is a credential file that will be committed the moment somebody types `git add .`,
    which is exactly the moment worth warning about, whether or not it has happened yet.
    """
    try:                                  # git handles nesting, negation and global excludes
        r = subprocess.run(["git", "-C", root, "check-ignore", "-q", rel],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return False                  # declared uncommittable
        if r.returncode == 1:
            return True                   # git answered: nothing is stopping it
    except (OSError, subprocess.SubprocessError):
        pass
    # No git here. Fall back to reading the declarations by hand.
    name = os.path.basename(rel)
    for d in (os.path.dirname(os.path.join(root, rel)), root):
        gi = os.path.join(d, ".gitignore")
        if not os.path.isfile(gi):
            continue
        try:
            for line in open(gi, encoding="utf8", errors="replace"):
                pat = line.strip()
                if not pat or pat.startswith("#"):
                    continue
                if pat.startswith("!") and pat.lstrip("!").strip("/") in (name, rel):
                    return True           # explicitly un-ignored
                if pat.strip("/") in (name, rel):
                    return False
        except OSError:
            pass
    return True


def _env_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if ENV_NAMES.match(fn):
                out.append(os.path.relpath(os.path.join(dirpath, fn), root))
    return sorted(out)


def _secrets_in(path):
    """(key, line) for every assignment whose value is a real credential."""
    found = []
    try:
        with open(path, encoding="utf8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip("\"'")
                if not SECRET_KEY.search(k):
                    continue
                if PLACEHOLDER.match(v) or PLACEHOLDER_SUBSTR.search(v):
                    continue
                if len(v) < 8:            # too short to be a working secret
                    continue
                found.append((k, n))
    except OSError:
        return None
    return found


def scan_secrets(root):
    """Committed credential files. Returns (findings, unreadable_or_None)."""
    root = os.path.abspath(root)
    findings = []
    for rel in _env_files(root):
        if TEMPLATE.search(rel):
            continue                      # a template is the remedy, not the defect
        path = os.path.join(root, rel)
        secrets = _secrets_in(path)
        if secrets is None:
            return None, rel              # could not read: no answer, not "no findings"
        if not secrets:
            continue
        if not _would_be_committed(root, rel):
            continue                      # declared uncommittable: not this rule's business
        names = ", ".join(k for k, _ in secrets[:4])
        findings.append({
            "tool": "secrets", "rule": "secrets/committed-credential-file",
            "file": rel, "line": secrets[0][1], "sev": "HIGH",
            "message": (f"`{rel}` is tracked in version control and carries "
                        f"{len(secrets)} credential value(s) that are not placeholders "
                        f"({names}). Anything ever pushed should be treated as disclosed."),
            "remedy": ("rotate every value in this file, then untrack it (`git rm --cached`) "
                       "and add it to .gitignore, keeping a committed template that carries "
                       "the keys and no values. Removing it in a new commit does not remove "
                       "it from history."),
        })
    findings.sort(key=lambda f: f["file"])
    return findings, None


if __name__ == "__main__":
    fs, bad = scan_secrets(sys.argv[1])
    if bad:
        print(f"unreadable: {bad}")
        sys.exit(2)
    print(f"{len(fs)} committed-credential finding(s)")
    for f in fs:
        print(f"  [{f['sev']}] {f['rule']} {f['file']}:{f['line']}\n      {f['message']}")
