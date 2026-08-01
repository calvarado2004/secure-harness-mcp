# What this pack does NOT cover

- **A bootstrap path is a file OR a function whose name looks like one** (`seed`, `init`,
  `bootstrap`, `fixture`, `demo_data`, `sample_data`). Reading only filenames meant the same
  defect was a finding in a repository's layout and invisible in a single-file application,
  whose bootstrap is `def init_db()` inside `app.py`. Both are read now. An administrator
  created in a function named none of those, or at module level in a file named none of
  those, is still missed.
- **Two spellings of "create this account" are read**: keyword arguments on a constructor
  (`User(role="admin", hashed_password=...)`) and a parameterised `INSERT` whose column list
  can be parsed. An account assembled field by field (`u = User(); u.role = "admin"`) is
  invisible, and so is an `INSERT` built by string concatenation or by an ORM bulk helper.
- **The raw-SQL detector requires the column list.** `INSERT INTO users VALUES (?, ?, ?)`
  with no columns named is not reported, because there is then no way to tell the username
  from the password, and a lane that guesses reports `("operator", NULL, "admin")`, which is
  the *fix*, as the defect. Silence there is deliberate.
- **It follows a credential one hop.** A local assigned a literal, or a literal wrapped in a
  known hasher, is resolved into the `INSERT` that binds it. A credential arriving through
  two variables, a helper function or a dict is not.
- **"Privileged" and "password" are name matches** against the shared vocabulary. A project
  using its own words for either needs them added.
- **It does not check whether the seed actually runs**, or runs only in development. A
  bootstrap script guarded by an environment check is still reported — reading that guard
  correctly is beyond a name-and-keyword match, and over-reporting is the safer direction.
