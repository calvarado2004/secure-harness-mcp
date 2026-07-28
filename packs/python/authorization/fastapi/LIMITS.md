# What this pack does NOT cover

Written here, in the pack, rather than in a paper someone will write later. A bespoke lane
whose limits are undocumented will be read as a complete one.

- **It does not prove exploitability.** It answers four structural questions whose "no" is
  nearly always a real defect. The behavioural battery is what proves an attack lands.
- **It does not model role hierarchies.** "Is an `editor` allowed to do this?" is outside
  it. It distinguishes only *no identity* / *identity but no decision about it* / *a
  decision*.
- **It does not model object-level ownership.** A handler that scopes its query by
  `current_user.id` is treated as having made an authorization decision. If it scopes by the
  wrong field, this lane will not notice.
- **It only understands dependencies declared in the handler signature.** Authorization
  applied by middleware, by a router-level `dependencies=[...]`, or by a decorator of the
  project's own is invisible to it and will be reported as missing. Add such helpers to
  `auth_deps` if they are called in the signature; otherwise expect false positives and
  reweight rather than suppress.
- **It reads FastAPI only.** Flask, Django and Starlette-without-FastAPI express routes
  differently and need their own framework pack. A repository using one of those and loading
  only this pack has an unread authorization axis, not a clean one.
- **`public_routes` is compared as a literal string** against `prefix + path`. A route whose
  prefix is computed at runtime will not match, and will be flagged.
