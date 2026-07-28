# What this pack does NOT cover

This pack **declares** rules and **detects nothing**. Its limits are therefore of a
different kind, and worth stating precisely because a rule with no detector loaded is the
easiest way for a policy to look bigger than it is.

- **A declared rule with no binding is not enforced.** If no language pack `binds` a rule
  here, it contributes nothing to any verdict. `packtest` does not currently fail on an
  unbound rule, because declaring an invariant before you can detect it is legitimate — but
  do not read the rule count as coverage.
- **Severity is declared once, for every runtime.** That is the point (comparable weights),
  and it is also a limitation: a defect that is genuinely worse in one runtime than another
  cannot say so here. Use `reweight:` in the language pack if that is ever true.
- **These are engineering invariants, not security rules.** They earn their weight by naming
  a concrete failure, not an attack. Do not let them dominate a security total; if one of
  them ever does, that is a signal to re-examine the weights, not the code.
- **Provenance is not proof of generality.** Every `failure` here records a defect observed
  in this project's own runs. That makes each rule real; it does not make it universal.
