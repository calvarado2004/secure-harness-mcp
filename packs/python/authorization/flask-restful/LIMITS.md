# What this lane cannot see, and what it refuses to say

## It reads the add_resource mount form, and shares the rest with the flask-restx lane

This lane reads flask-restful `Resource` classes mounted with `api.add_resource(Cls, "/path")`,
the third Flask mounting form. Plain `@bp.route` view functions are also counted so a repository
using both spells one defect once, but the class-plus-namespace shape of flask-restx belongs to
the `python/authorization/flask-restx` pack, and `MethodView`/`flask.views`, blueprints whose
prefix is computed at runtime, and resources mounted through a factory are **not read**. The
mount resolution reads `Blueprint(url_prefix=...)` and the `add_resource` path arguments as
literals; a prefix built by string arithmetic resolves to the empty string and every
declared-intent lookup for those routes then misses.

## The write-side rule reasons about CONVENTION, not about inline logic

`authz/mutation-guard-weaker-than-siblings` fires where a mutating verb omits the guard its
sibling verbs on the same resource carry. It is blind to a guard expressed as INLINE code rather
than as a decorator its siblings share: the sibling FastAPI subject (Aegra, GHSA-m98r-6667-4wq7)
carries `Depends(auth)` on every route and enforces ownership with an inline
`existing.user_id != user.identity` check, and this lane does not read that. Convention deviation
is what it detects; a uniformly-decorated API with a missing inline check reads as clean here.

## Three restrictions, each of which hides real defects

Every one trades recall for precision, deliberately:

- **Corroboration.** A guard carried by fewer than three handlers repository-wide is treated as
  a coincidence, not a convention. A project that guards exactly two writes correctly and a
  third incorrectly gets no finding.
- **Resource locality.** The comparison is within one mounted path. A write whose siblings live
  on a different resource, or a resource with only one mutating verb, is not compared.
- **Dominance.** A handler carrying a guard named in `dominating_guards` is skipped. If a
  project's `admin_permission.require` is in practice weaker than the per-resource check, this
  lane is wrong.

## A validator is not a guard, and the lane learned this the hard way

The first version of the sibling rule counted any decorator two mutating siblings shared as the
convention, and reported `validate_schema` — a request-body validator — as a missing guard. It
reported it identically on the vulnerable and the patched tree, which is how it was caught: a
finding that does not move across the fix is not the defect. The guard-name test exists because
of that run, and the negative control covers it.

## It needs the project to say what subsumes what, and nothing more

`dominating_guards` names the guard an administrator already holds, so an admin-only handler is
not also asked for a per-resource check. `protected_data` may be empty, and is for the subject
this pack was written for: the write-side rule needs no disclosure policy. A profile that instead
named the vulnerable endpoint, file or guard would be recording an answer, and the finding would
prove nothing about any other repository.

## It does not prove exploitability

A finding is a structural inconsistency with the project's own practice, not a demonstrated
attack. `HIGH` here means "the project guards this verb everywhere else on this kind of
resource", not "exploited". Whether the write is reachable by an under-privileged caller is the
behavioural battery's question.
