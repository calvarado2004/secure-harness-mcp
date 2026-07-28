#!/usr/bin/env python3
"""Fidelity oracle for a repository: what routes exist, and did repair change the surface.

In the greenfield study fidelity was measured against a WRITTEN specification: the prompt
named fourteen endpoints, so implemented-versus-specified was well defined. A brownfield
project has no such document. The specification IS the baseline -- whatever the repository
served before repair is what it must still serve after.

That makes the two directions concrete and, usefully, harder to game than the greenfield
version:
  routes        endpoints the tree still exposes. Losing one is harm, full stop.
  extra_routes  endpoints repair INVENTED. A security fix has no business adding surface,
                and an agent that "fixes" authorization by publishing a new admin endpoint
                should be rejected rather than congratulated.

Resolution is static (AST), not by importing the app, so it still answers on a tree whose
imports the agent has just broken -- which is exactly when the gate needs an answer.
"""
import ast
import json
import os
import sys

METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}
SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "images"}


def _router_prefixes(tree):
    """Map local router variable -> prefix, from `APIRouter(prefix="/x")` assignments."""
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        fn = node.value.func
        name = getattr(fn, "id", None) or getattr(fn, "attr", None)
        if name not in ("APIRouter", "FastAPI"):
            continue
        prefix = ""
        for kw in node.value.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                prefix = kw.value.value
        for t in node.targets:
            if isinstance(t, ast.Name):
                out[t.id] = prefix
    return out


def routes_in(path):
    """Every (METHOD, path) the module declares, with its router prefix applied."""
    try:
        tree = ast.parse(open(path, encoding="utf8", errors="replace").read())
    except SyntaxError:
        return None                      # unparseable: no answer, not an empty answer
    prefixes = _router_prefixes(tree)
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            fn = dec.func
            if not isinstance(fn, ast.Attribute) or fn.attr not in METHODS:
                continue
            owner = getattr(fn.value, "id", None)
            route = ""
            if dec.args and isinstance(dec.args[0], ast.Constant):
                route = dec.args[0].value
            full = (prefixes.get(owner, "") + route) or "/"
            found.add((fn.attr.upper(), full))
    return found


def edge_routes(repo):
    """Location prefixes the reverse proxy publishes.

    WHY THE EDGE IS PART OF FIDELITY, ADDED BEFORE THE gen3 RUN RATHER THAN AFTER IT.
    The nginx lane reports `nginx/proxies-backing-service` on the location that serves
    vehicle images. Ask the question HARNESS-EXTENSION.md §3 insists on -- can the model
    improve this score by removing the thing being measured? -- and the answer is yes:
    delete the location block and the finding disappears. The functional oracle cannot
    object, because it drives the app directly and says so in its own docstring: "MinIO and
    nginx are not exercised. Storage and proxy regressions are invisible here."

    So the proxy's published prefixes become a fidelity coordinate, exactly like the API
    surface. Losing one is harm whether or not any probe would have noticed. This costs
    nothing at runtime -- it is a static read of the config -- and it closes the one route
    by which a gen3 finding could be "fixed" by breaking the product.
    """
    import re
    # Prefixes a gen3 rule ASKS the model to remove. They must not count toward fidelity,
    # or the gate refuses the very fix the security lane requested -- a harness trapping the
    # model, which is the failure mode this project has now hit five times and caught in
    # advance exactly once. This is that once.
    remediable = ("/docs", "/redoc", "/openapi.json", "/swagger", "/graphql")
    out = set()
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(".conf"):
                continue
            try:
                src = open(os.path.join(dirpath, fn), encoding="utf8",
                           errors="replace").read()
            except OSError:
                return None                      # unreadable: no answer, not "none"
            for m in re.finditer(r"location\s+([^\s{]+(?:\s+[^\s{]+)?)\s*\{", src):
                loc = m.group(1).strip()
                if any(loc.lstrip("~*= ").startswith(r) for r in remediable):
                    continue
                out.add(loc)
    return sorted(out)


def inventory(repo):
    """The route surface of the whole tree, plus measurability."""
    repo = os.path.abspath(repo)
    all_routes, unparsed = set(), []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            r = routes_in(p)
            if r is None:
                unparsed.append(os.path.relpath(p, repo))
            else:
                all_routes |= r
    return {"routes": sorted(all_routes), "edge_routes": edge_routes(repo),
            "unparsed": unparsed,
            "measured": not unparsed}


def compare(repo, baseline_routes, baseline_edge=None):
    """Score a candidate tree against the surface the project started with."""
    inv = inventory(repo)
    if not inv["measured"]:
        return {"routes": 0, "extra_routes": 0, "edge_routes": 0, "measured": False,
                "unmeasurable": "route surface unreadable: "
                                + ", ".join(inv["unparsed"])}
    have = {tuple(r) for r in inv["routes"]}
    base = {tuple(r) for r in baseline_routes}
    edge = inv.get("edge_routes")
    n_edge = (len(set(edge) & set(baseline_edge)) if baseline_edge is not None
              and edge is not None else (len(edge) if edge is not None else 0))
    return {"edge_routes": n_edge,
            "routes": len(have & base),          # of the original surface, how much survives
            "extra_routes": len(have - base),    # surface repair invented
            "measured": True, "unmeasurable": None,
            "lost": sorted(base - have), "added": sorted(have - base)}


if __name__ == "__main__":
    inv = inventory(sys.argv[1])
    print(json.dumps(inv, indent=1))
    print(f"{len(inv['routes'])} routes, measured={inv['measured']}")
