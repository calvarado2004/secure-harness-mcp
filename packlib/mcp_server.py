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
        from .inspect_repo import inspect
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
        from .inspect_repo import guidance
        return guidance(profile_or_fail(profile), repo, path)

    return mcp


def main():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("secure-harness-packs")
    register(mcp)
    mcp.run()


if __name__ == "__main__":
    main()
