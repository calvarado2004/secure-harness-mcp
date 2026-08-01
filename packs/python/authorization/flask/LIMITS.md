# What this pack does NOT cover

- **It reads Flask only.** FastAPI has its own framework pack; Django, Starlette and Quart
  express routes and guards differently and need theirs. A repository using one of those and
  loading only this pack has an unread authorization axis, not a clean one.
- **A guard is recognised by NAME, not by behaviour.** A decorator, or a helper called in the
  body, counts when its name carries one of `auth`, `login`, `role`, `permission`, `admin`,
  `jwt`. A guard named nothing like any of those is invisible and its handler will be
  reported as unguarded; a decorator named `require_auth` that does nothing is accepted. Add
  project-specific names to `auth_decorators` rather than living with either error.
- **`decision-without-denial` fires only on an INERT branch.** The matching branch must be
  `pass`, `...`, or a bare docstring, with no `else`. A handler that records the decision
  into a variable and then mishandles it further down is doing work this lane cannot follow,
  and is missed. Reporting it would be a guess, and the price of not guessing is this gap.
- **An undeclared route is never a gated finding.** Routes the project has said nothing about
  produce advisories. That is deliberate (see `undeclared_route_verdict` in `pack.yaml`), and
  it means a genuinely exposed endpoint that nobody classified will be reported quietly
  rather than loudly. The fix is to classify it, which is the point.
- **It does not model role hierarchies.** "May an `editor` do this?" is outside it. It
  distinguishes only *no identity* / *identity but no decision* / *a decision made* /
  *a decision made and discarded*.
- **It does not model object ownership beyond control flow.** A handler that scopes a query
  by the caller is treated as having authorized. If it scopes by the wrong field, or compares
  the wrong two values, this lane will not notice.
- **It does not prove exploitability.** The behavioural battery does that. Every finding here
  is a structural question whose "no" is usually a defect, never a demonstrated attack.
- **`sensitive_routes` is matched as a literal string** against the route path with its
  parameters stripped, plus a prefix match. A route whose path is computed at runtime will
  not match and will be treated as undeclared.
