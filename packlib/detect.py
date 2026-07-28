#!/usr/bin/env python3
"""Route every file in a repository to the runtime that claims it.

WHY THIS EXISTS
A real project is polyglot. The dealership subject is Python plus a browser frontend plus a
compose file, and the single most reachable vulnerability in it lived in the one of those
three that the Python engines never open. So the harness cannot ask "what language is this
project?" — it has to ask, file by file, "which execution environment does this run in, and
which packs read that?"

THE RULE THAT MATTERS MORE THAN THE ROUTING
A file that no runtime claims is NOT skipped quietly. It is reported as unread. Ninety
percent of the defects this project has documented in its own instruments have the same
shape: something could not be measured, the total did not say so, and the absence read as
absence of a problem. An unclaimed file is that shape exactly. `inventory()` therefore
returns three things — what was claimed and has lanes, what was claimed but has NO lanes
(a declared runtime nobody has written rules for yet), and what nothing claimed at all —
and the caller is expected to print all three.

DETECTION IS DECLARED, NOT INFERRED. Every rule comes from a runtime pack's `detect:` block,
so a practitioner can always answer "why was this file read as Python?" by pointing at a
line in a file. Ambiguity is resolved by explicit specificity, never by guessing: `.js` is
claimed by `browser-js` and by `node-js`, and the profile decides which is loaded.
"""
import os
import re


class Inventory:
    """What is in this repository, and who can read it."""

    def __init__(self):
        self.by_runtime = {}      # runtime -> [relpaths]
        self.unclaimed = []       # no runtime pack claims these
        self.skipped = []         # (relpath, reason) — declared exclusions
        self.lanes_for = {}       # runtime -> bool, does any loaded pack give it lanes

    def add(self, runtime, rel):
        self.by_runtime.setdefault(runtime, []).append(rel)

    @property
    def unread(self):
        """Claimed by a runtime that has no lanes loaded: declared blind spots."""
        return {rt: fs for rt, fs in self.by_runtime.items() if not self.lanes_for.get(rt)}

    def report(self):
        out = []
        for rt in sorted(self.by_runtime):
            n = len(self.by_runtime[rt])
            mark = "read" if self.lanes_for.get(rt) else "UNREAD (no lanes loaded)"
            out.append(f"  {rt:<12} {n:>4} files   {mark}")
        if self.skipped:
            out.append(f"  {'(excluded)':<12} {len(self.skipped):>4} files   "
                       f"declared exclusions, e.g. minified bundles")
        if self.unclaimed:
            out.append(f"  {'(unclaimed)':<12} {len(self.unclaimed):>4} files   "
                       f"NO RUNTIME CLAIMS THESE — blind spot")
            for f in self.unclaimed[:8]:
                out.append(f"                    {f}")
            if len(self.unclaimed) > 8:
                out.append(f"                    ... and {len(self.unclaimed) - 8} more")
        return "\n".join(out)


def _shebang(path):
    try:
        with open(path, "rb") as f:
            first = f.readline(200).decode("utf8", "replace")
    except OSError:
        return ""
    return first[2:].strip() if first.startswith("#!") else ""


def _matches_content(path, spec):
    ext = os.path.splitext(path)[1]
    if spec.get("extensions") and ext not in spec["extensions"]:
        return False
    try:
        with open(path, encoding="utf8", errors="replace") as f:
            head = f.read(4096)
    except OSError:
        return False
    if not re.search(spec["pattern"], head, re.M):
        return False
    req = spec.get("requires")
    return not req or bool(re.search(req, head, re.M))


def claim(path, detectors):
    """Which runtimes claim this file? Returns a list, most specific evidence first."""
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1]
    hits = []
    for runtime, d in detectors.items():
        if name in (d.get("filenames") or []):
            hits.append((0, runtime))                       # exact filename: strongest
            continue
        for spec in (d.get("content_match") or []):
            if _matches_content(path, spec):
                hits.append((1, runtime))                   # content evidence
                break
        else:
            sb = d.get("shebang")
            sbs = [sb] if isinstance(sb, str) else (sb or [])
            if sbs:
                line = _shebang(path)
                if line and any(s in line for s in sbs):
                    hits.append((1, runtime))
                    continue
            if ext and ext in (d.get("extensions") or []):
                hits.append((2, runtime))                   # extension: weakest
    hits.sort()
    return [rt for _, rt in hits]


def inventory(root, detectors, skip_dirs, skip_globs=(), lanes_for=None,
              preferred=()):
    """Walk `root` and route every file. `preferred` breaks ties between runtimes."""
    import fnmatch
    root = os.path.abspath(root)
    inv = Inventory()
    inv.lanes_for = dict(lanes_for or {})
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if any(fnmatch.fnmatch(fn, g) for g in skip_globs):
                inv.skipped.append((rel, "declared exclusion"))
                continue
            hits = claim(full, detectors)
            if not hits:
                # Report unless the file is plainly an asset or prose. This was an ALLOWLIST
                # of code-looking extensions, and it under-reported exactly the way an
                # allowlist always does: `nginx.conf` -- a reverse proxy config that
                # terminates TLS, sets security headers and decides what is publicly
                # routable -- was claimed by no runtime AND reported by no inventory,
                # because `.conf` was not on the list. An external scan noticed it and we
                # had not. A blind spot that the blind-spot report cannot see is the worst
                # case this system has.
                if not _is_asset(fn):
                    inv.unclaimed.append(rel)
                continue
            if len(hits) > 1 and preferred:
                for p in preferred:
                    if p in hits:
                        hits = [p]
                        break
            inv.add(hits[0], rel)
    return inv


# A DENYLIST, deliberately. Anything that is not obviously a binary asset or prose gets
# reported when nothing claims it -- configuration files decide security posture as surely
# as code does, and there is no finite list of the ones that matter. The cost of the other
# direction is a few noisy lines; the cost of this direction was a reverse-proxy config
# nobody could see.
_ASSET_EXT = {
    # images / media / fonts
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".mp3", ".mp4", ".mov", ".avi", ".webm", ".wav",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    # archives / compiled artifacts
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".whl", ".jar", ".war",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".pyo",
    ".pdb", ".db", ".sqlite", ".sqlite3",
    # prose and lockfiles: real, but not a security surface anyone reads with a lane
    ".md", ".rst", ".txt", ".csv", ".pdf", ".lock",
}
_ASSET_NAMES = {".DS_Store", ".gitkeep", ".gitattributes", "LICENSE", "NOTICE"}


def _is_asset(fn):
    return os.path.splitext(fn)[1].lower() in _ASSET_EXT or fn in _ASSET_NAMES
