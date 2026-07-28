# What this pack does NOT cover

- **"Reaches the resource" is an AST name match.** A handler that returns a `Customer` via a
  helper that never names the model is not seen; a handler that mentions `Customer` in a
  docstring-free type annotation but returns something else is.
- **It compares handlers of the same model only.** Divergence between two models that should
  share a guard is invisible.
- **"Guarded" means an identity dependency appears in the handler.** It does not check that
  the guard is *correct* — that is the authorization lane's first question and the
  behavioural battery's answer.
- **The detector is shared with the browser practice lane** (`repo_practice.scan_practice`
  walks both). Its Python half is what this pack binds; the browser half belongs to
  `browser-js/practice`.
