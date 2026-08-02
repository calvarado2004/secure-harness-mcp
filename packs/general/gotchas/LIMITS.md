# What this pack cannot see

## It is two rules, not a scanner

This pack holds only the policy-free classes that `bandit` and Semgrep were measured to miss.
It is not a general-purpose analyser and a clean result from it says nothing about hardcoded
secrets, debug flags, TLS verification, deserialisation or command execution, all of which are
the commodity engines' job and all of which run alongside it.

## Configuration it cannot follow

Both rules read literal assignments. A project that builds its CORS origins from an
environment variable, a settings object, or a helper that returns `"*"` under some branch is
**not seen**. The same holds for cookie flags set through a framework's settings module rather
than assigned in code. Absence of a finding is not evidence of absence.

## Deployment context is inferred from paths

A file is treated as development-only when its path contains a directory such as `tests` or
`.devcontainer`, or its name suggests it. A project that ships its production compose from a
directory called `examples`, or keeps a developer stack at the repository root, will be
classified the wrong way. The classification only ever moves a finding between gated and
advisory; it never hides one.

## It does not prove exploitability

`cors/wildcard-with-credentials` describes a reachable configuration, not a demonstrated
attack. Whether a given deployment is exploitable depends on what the API returns to a
credentialed caller, which the behavioural battery decides.
