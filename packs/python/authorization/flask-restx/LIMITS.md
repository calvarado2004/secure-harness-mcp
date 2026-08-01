# What this lane cannot see, and what it refuses to say

## It reads one route form, and says nothing about the others

This lane reads flask-restx `Resource` classes mounted with `@<namespace>.route(...)`. A
project that also registers plain Flask view functions needs the `python/authorization/flask`
pack for those; this pack does not read them and does not pretend to. Both bind the same rule
ids, so a repository using both spells one defect once.

Route forms it does **not** read: `MethodView` / `flask.views`, `add_resource(...)` called
imperatively instead of the decorator, blueprints registered through a factory whose prefix is
computed at runtime. The mount resolution reads `Blueprint(url_prefix=...)` and
`Api.add_namespace(ns, "/prefix")` as literals. A prefix built by string arithmetic resolves
to the empty string, and every declared-intent lookup for those routes then misses.

## The one-hop reach is a floor, not a bound

To decide whether a handler discloses a protected attribute the lane follows calls **one hop**
into functions defined in the same repository. The handler that motivated this pack returns
nothing identifying on its own face; it calls a helper, and the account name is selected
inside that helper. Two hops would find more and would also drag in enough vocabulary to make
the signal meaningless, so one hop is the deliberate compromise. A disclosure that passes
through two helpers, a class method, or an imported third-party serializer is **not seen**.
Absence of a finding here is not evidence of absence.

## It needs the project to say what is private

With no `protected_data` the lane reports nothing, and that is the correct answer rather than a
degenerate one. "Is this endpoint authorized?" has no general answer: it depends on who may see
what, which lives in the project and not in its syntax. What the project supplies is a policy
("account identity is not public; a handler discloses it by projecting a name, username or
email"). What the lane supplies is the guard, the evidence that the project has established
it, and the deviating site. A profile that instead named the endpoint would be recording an
answer, and the finding would prove nothing about any other repository.

## Three restrictions, each of which hides real defects

Every one of these trades recall for precision, deliberately, and each will miss things:

- **Corroboration.** A guard carried by fewer than three handlers is treated as a coincidence.
  A project that protects exactly two endpoints correctly and a third incorrectly gets no
  finding.
- **Dominance.** A handler carrying a guard named in `dominating_guards` is skipped. If a
  project's `admins_only` is weaker than its visibility guard, this lane is wrong.
- **Reads only.** A visibility guard controls disclosure, so only read verbs are asked. A
  write that leaks the protected attribute in its response body is not flagged.

## It does not prove exploitability

A finding is a structural inconsistency with the project's own practice, not a demonstrated
attack. Whether the disclosed record is one an attacker can actually reach is the behavioural
battery's question. `HIGH` here means "the project protects this everywhere else", not
"exploited".
