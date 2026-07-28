# What this pack does NOT cover

- **It reads the policy the code would set, not the bucket's live policy.** If the policy
  was changed by hand after deployment, this lane describes the source and not the system.
- **It reads policy documents in modules that also call `set_bucket_policy`.** A policy
  assembled in one module and applied in another is missed; a policy built and never applied
  is correctly ignored.
- **f-string interpolation folds to `*`.** A bucket or prefix name computed at runtime is
  treated as unknown, which makes the resource look broader than it may be. That direction
  is deliberate — over-reporting a grant is safer than under-reporting one — but it is a
  false-positive source on heavily templated policies.
- **It does not check IAM roles, ACLs, bucket ownership, or object-level ACLs**, all of
  which can grant access this lane never sees. A silent result is not "the bucket is
  private".
- **No encryption-at-rest, versioning, lifecycle or logging rules.** Each failed the
  "can you state the attack?" test at the weight it would have carried here.
