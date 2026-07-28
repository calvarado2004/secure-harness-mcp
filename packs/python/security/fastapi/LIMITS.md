# What this pack does NOT cover

- **It reports the BINDING, not the flow.** It says a credential-named value is read from
  the query string. It does not track where the value goes, and it does not need to — the
  URL has already been logged by then.
- **It matches parameter names.** A credential passed as `q`, `data` or `x` is invisible.
  Renaming to evade it is possible and pointless, but a genuinely unusual naming convention
  will be missed.
- **It only understands FastAPI's binding rules.** Flask, Django and Starlette bind
  parameters differently; a repository using one of those and loading this pack has an
  unread binding surface, not a clean one.
- **`Annotated[str, Query()]` is read as a scalar**, which is correct, but an explicit
  `Query(...)` default is *deliberate* query binding — the lane still reports it, and that
  is intended: deliberately putting a password in the query string is the defect, not an
  exemption from it.
- **`py/undeclared-api-introspection` is skipped entirely without `public_routes`.** It
  reports nothing rather than guessing, so its silence in a profile that supplies no facts
  means nothing at all.
- **It does not check that the credential is verified correctly** once bound. That is the
  authorization lane's question and the behavioural battery's answer.
