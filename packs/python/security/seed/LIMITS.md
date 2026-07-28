# What this pack does NOT cover

- **Only files whose name looks like a bootstrap path** (`seed`, `init`, `bootstrap`,
  `fixture`, `demo_data`, `sample_data`) are read. An administrator created in
  `manage.py` or in a test helper that runs against a real database is missed.
- **It matches keyword arguments on a constructor call.** An account assembled field by
  field (`u = User(); u.role = "admin"; u.password = ...`) is invisible.
- **"Privileged" and "password" are name matches** against the shared vocabulary. A project
  using its own words for either needs them added.
- **It does not check whether the seed actually runs**, or runs only in development. A
  bootstrap script guarded by an environment check is still reported — reading that guard
  correctly is beyond a name-and-keyword match, and over-reporting is the safer direction.
