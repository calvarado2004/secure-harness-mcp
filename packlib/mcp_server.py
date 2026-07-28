#!/usr/bin/env python3
"""The pack system, exposed over MCP.

Two tools, and they answer the two questions an agent working in an unfamiliar polyglot
repository actually has:

  repo_inventory   what is in this repository, which lanes will run on it, and — the part
                   nobody asks — which files NOTHING reads.
  module_guidance  which rules apply to THIS module, because of the language it is written
                   in, plus the project's own declared facts and deployment context.

TWO ENTRY POINTS, ONE DEFINITION. `register(mcp)` adds the tools to an existing FastMCP
server (the experiment's three-axis server calls this), and `main()` runs them standalone.
They are the same functions. A second copy of a tool definition is a second source of truth,
and this project has already paid for one of those.

    python -m packlib.mcp_server            # standalone server over stdio
"""
import glob
import os
import sys

if __package__ in (None, ""):
    # Running as a plain script path -- `python /abs/path/to/packlib/mcp_server.py`, which is
    # how most MCP clients spell a command. Without this the relative import below fails with
    # "attempted relative import with no known parent package" and the server never starts.
    # `python -m packlib.mcp_server` works too, but only from the repository root, and a
    # client config that must also set a working directory is a config that gets set wrong.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from packlib.loader import PROJECTS
else:
    from .loader import PROJECTS


def profile_or_fail(explicit):
    """Which project profile to answer with — never a silent default.

    A profile carries one project's FACTS: which dependencies establish identity, which
    routes are public on purpose, which models are sensitive. Answering about repository A
    with repository B's facts produces confident, specific, wrong advice, and it looks
    exactly like correct advice. So the profile is explicit, or comes from the environment
    the server was started in, or the call fails saying which ones exist.
    """
    name = explicit or os.environ.get("HARNESS_PROFILE", "")
    if name:
        return name
    have = sorted(os.path.basename(f)[:-5] for f in glob.glob(os.path.join(PROJECTS, "*.yaml")))
    raise ValueError(
        f"no project profile given. Pass `profile=`, or start the server with "
        f"HARNESS_PROFILE set. Available: {have}. There is deliberately no default: "
        f"answering about one repository with another's facts is confident, specific and "
        f"wrong, and looks identical to being right.")


def make_server(name):
    """A FastMCP-shaped server across both major versions of the `mcp` package.

    THIS EXISTS BECAUSE A FRESH INSTALL WAS BROKEN AND NOTHING SAID SO. `requirements.txt`
    asked for `mcp>=1.2`; that resolved to 1.27 when the code was written and resolves to
    2.0 today, which moved `mcp.server.fastmcp` to `mcp.server.mcpserver.MCPServer`. Every
    developer machine here already had 1.27 installed, so the server started fine for us and
    died on `ModuleNotFoundError` for anyone installing from the requirements file.

    Both classes expose a compatible `.tool()` decorator and `.run()`, so the fix is a shim
    rather than a version pin -- pinning would work today and quietly rot in the other
    direction. The failure is loud if BOTH imports fail, because a server that cannot start
    should say why, not disappear.
    """
    try:                                            # mcp 1.x
        from mcp.server.fastmcp import FastMCP
        return FastMCP(name)
    except ImportError:
        pass
    try:                                            # mcp 2.x
        from mcp.server.mcpserver import MCPServer
        return MCPServer(name)
    except ImportError as e:
        raise ImportError(
            "neither mcp.server.fastmcp (mcp 1.x) nor mcp.server.mcpserver (mcp 2.x) could "
            f"be imported: {e}. Install the dependencies with "
            "`pip install -r requirements.txt`.") from e


def register(mcp):
    """Add the pack tools to a FastMCP server. Returns the server, for chaining."""

    @mcp.tool()
    def repo_inventory(repo: str, profile: str = "") -> dict:
        """Route every file in a repository to the language packs that read it.

        Returns, per runtime: how many files, which lanes will run, and which packs are
        loaded — plus two blind-spot categories kept deliberately separate. `unread` means a
        runtime is recognised and no rules exist for it yet; `unclaimed` means no runtime
        pack even recognises the file. Neither is a clean result, and a zero from a scan
        says nothing about either.

        Call this BEFORE reviewing anything, so you know what the review will not cover.
        """
        from packlib.inspect_repo import inspect
        return inspect(profile_or_fail(profile), repo)

    @mcp.tool()
    def module_guidance(repo: str, path: str, profile: str = "") -> dict:
        """The rules, remedies and project facts that apply to ONE module, by its language.

        A `.py` module gets the Python packs; a `.html` module gets the browser packs. Both
        get the shared layers — the general vocabulary, the organisation's standards, and
        the project's declared facts (which dependencies establish identity, which routes
        are public on purpose, which models are sensitive). That is what keeps a polyglot
        repository coherent: one set of facts, many detectors.

        Each rule carries four things worth reading before you change code:
          remedy    — what to do
          attack    — what an attacker gets if you do not (security rules)
          failure   — what breaks if you do not (practice rules)
          overreach — what a TOO-STRICT application of this rule breaks in a real
                      deployment. Least privilege is the goal; a fix that satisfies the rule
                      and breaks the deployment gets reverted, taking the protection with
                      it. Read this before proposing the maximal fix.
        """
        from packlib.inspect_repo import guidance
        return guidance(profile_or_fail(profile), repo, path)

    return mcp


def selftest():
    """Prove the server can be BUILT and its tools registered, without speaking stdio.

    Cheap enough to run in a Docker build and in `brew test`, which is the point: the last
    two things that broke here were a distribution that omitted whole directories and a
    dependency range that resolved to an incompatible major. Both produced a server that
    could not start, and both were invisible until someone tried to use it.
    """
    mcp = make_server("secure-harness-packs")
    register(mcp)
    import asyncio
    names = sorted(t.name for t in asyncio.run(mcp.list_tools()))
    want = ["module_guidance", "repo_inventory"]
    ok = names == want
    print(f"server builds: {type(mcp).__name__}")
    print(f"tools registered: {names}")
    print("[PASS] the pack MCP server starts and registers both tools" if ok
          else f"[FAIL] expected {want}")
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    mcp = make_server("secure-harness-packs")
    register(mcp)
    mcp.run()


if __name__ == "__main__":
    main()
