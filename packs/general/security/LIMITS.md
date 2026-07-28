# What this pack does NOT cover

Like `general/practice`, this pack **declares** and detects nothing. Its limits are of that
kind:

- **A declared rule with no binding is not enforced.** If no language pack binds
  `seed/default-admin-credential`, it contributes to no verdict. Do not read the rule count
  as coverage.
- **One severity for every runtime.** That is the point — a HIGH here means the same thing
  wherever it fires — and it is a limitation if a defect is genuinely worse in one runtime.
- **"Privileged" is a vocabulary match**, shared with `general/`'s `priv_fields` and the
  role words. A project whose admin flag is called something unusual needs that word added.
