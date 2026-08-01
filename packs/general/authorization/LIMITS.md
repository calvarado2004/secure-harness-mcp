# What this pack does NOT cover

- **It declares invariants and detects nothing.** Every rule here is bound by a framework
  pack that can read the framework's own spelling of a guard. A repository whose framework
  has no such pack has an UNREAD authorization axis, not a clean one, and the inventory
  reports it that way.
- **It does not model role hierarchies or object ownership.** The rules distinguish only
  *no identity required* / *identity required but no decision made* / *a decision made*.
  Whether an `editor` may edit this particular row is outside all three.
- **`client-settable-privilege` assumes a privilege model exists.** A project with no roles
  at all, which is the case for some perfectly secure applications, will never fire it, and
  that silence says nothing about the project's authorization.
- **The worked examples belong to the bindings, not to the rules.** The remedy prose here is
  framework-neutral by necessity and therefore vaguer than a framework's own. A binding that
  attaches a reference gives its framework a concrete fix; one that does not leaves the
  model with prose.
