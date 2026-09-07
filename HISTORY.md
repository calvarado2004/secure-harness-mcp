# Why the harness is maintained with the project

The MCP server supplies extensible infrastructure for repository inspection,
policy definition and executable checks. It does not predict defects in unseen
repositories. Once the team establishes an acceptable MVP and its checks,
subsequent work is checked and repaired against that contract. Periodic review
can reveal new requirements or incorrect checks, requiring changes to the
harness itself.

The implementation history records that work:

- `963dd59`: added FastAPI parameter-binding and nginx readers with controls.
- `b3ff60c`: added object-store and compose readers; checked the declared
  published-service list and corrected the profile's wrong service name.
- `d081690`: corrected a remedy that asked the repair agent to alter policy
  outside its ownership, separating code repair from the owner's decision.
- `7e275ee` and `4b7f3ad`: stopped ignore rules from an enclosing repository
  being treated as the scanned project's declarations.
- `5e9cfcf`: corrected the compose reader's treatment of literal credential
  fallbacks inside environment substitutions.
- `e56165f` and `2be2099`: added Lemur's mount parser, write-side rule and
  pack binding so MCP could select the new lane.

Inspect each source change with `git show <revision> -- <path>`. The paper's
`evidence/HARNESS-HISTORY.md` gives paths, full revision identifiers and the
distinction between implementation changes and recorded run outcomes.
Historical commit subjects remain unchanged, including earlier misleading
references to unseen code; the current scope is defined in `AGENTS.md` and
the README. These cases document actual maintenance, not a measured speedup
over another tool or proof of complete coverage.
