# What this pack does NOT cover

- **There is no TypeScript parser here.** The lane is a brace-matching scanner over source
  text. It reads a route's argument list, the middleware in it and the handler body. It
  cannot follow a chain assembled at runtime, a router returned by a helper, middleware
  applied with `router.use()` above the routes, or a guard composed inside another function.
  Any of those reads as an unguarded route.
- **A guard is recognised by NAME.** `auth_middleware` and `optional_auth_middleware` are
  project facts. A guard named nothing in those lists is invisible and its route will be
  reported; a middleware named `authenticate` that authenticates nothing is accepted.
- **`router.use()` is not read.** A router that applies identity middleware to every route
  above the definitions is a common and correct pattern, and this lane will report every
  route beneath it. Declare those routes sensitive and fix the lane before trusting it on a
  codebase that uses the pattern.
- **Undeclared routes are advisories, never gated findings.** A project that has not said
  whether an endpoint is public gets an observation rather than a work item. That is
  deliberate: this subject serves a deliberately public user profile through a projection
  that selects a username, an avatar and a rating, and gating on it would tell a correct
  product to break itself.
- **It does not model roles or ownership.** This subject has no privilege model at all, so
  `authz/client-settable-privilege` is not bound here. A Node project that does have roles
  needs that binding written and controlled before the axis means anything.
- **It reads Express.** Fastify, Koa, NestJS and bare `http` express routes differently and
  each needs its own framework pack.
