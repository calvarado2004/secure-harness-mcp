# Seeding a database without shipping a credential

The bootstrap account is necessary. Somebody has to be able to log in before anybody can be
granted anything, and every real deployment needs demo or reference data. None of that is
the defect. The defect is that the credential which unlocks the account is written in a file
that is committed, imaged, published and identical on every deployment.

Three mechanisms, in the order you should prefer them. All three keep the seed doing its
job.

## 1. No usable credential at all (preferred)

Create the account disabled, with no password set, and set the password out of band — a
one-time link, a console command, or the operator's own first login flow. Nothing secret
exists in the repository, so nothing secret can leak from it.

```python
admin = User(
    username="admin",
    email=os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "admin@example.invalid"),
    hashed_password=None,        # unusable: no password can match
    is_active=False,             # and it cannot log in until an operator enables it
    role="admin",
)
```

```sql
INSERT INTO users (username, hashed_password, role, is_active)
VALUES ('admin', NULL, 'admin', false);
```

A `NULL` hash must fail every verification path. Check that: a comparison routine that
treats `None` as "no password required" turns this fix into a worse defect than the one it
replaced, and that mistake is common enough to be worth a test.

## 2. Required from the environment

If the account must be usable the moment the stack comes up, take the secret from the
environment and **refuse to seed without it**. The refusal is the part that matters: a
default makes this identical to hardcoding.

```python
pw = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
if not pw:
    raise SystemExit(
        "BOOTSTRAP_ADMIN_PASSWORD is required to seed the administrator. "
        "Set it, or seed with mechanism 1 and set the password out of band."
    )
admin = User(username="admin", hashed_password=hash_password(pw), role="admin")
```

```yaml
# compose: required, with no fallback. `:?` fails the run if it is unset.
environment:
  BOOTSTRAP_ADMIN_PASSWORD: ${BOOTSTRAP_ADMIN_PASSWORD:?set this before starting}
```

`${VAR:-default}` is NOT this mechanism. A default is a hardcoded credential with extra
steps, and it is the shape that ships to production most often, because everything works
locally and nobody notices the fallback was used.

## 3. Generated once, printed once, never stored

For a demo stack where nobody wants to manage a secret, generate a strong password at seed
time, print it to the log, and do not persist it anywhere else.

```python
import secrets
pw = secrets.token_urlsafe(24)
admin = User(username="admin", hashed_password=hash_password(pw), role="admin")
db.add(admin)
print(f"[seed] bootstrap administrator password (shown once): {pw}", flush=True)
```

Use `secrets`, never `random` — `random` is seeded predictably and its output can be
reconstructed. This mechanism is fine for a demo and wrong for anything shared, because the
password ends up in log storage.

## What stays the same in all three

- Seed **unprivileged** demo rows however you like. A literal password on a `role="user"`
  fixture grants nothing and is not this rule's concern.
- Keep seeding **idempotent** — check for the account before creating it — so a restart does
  not reset a password an operator has since changed.
- Do not "fix" this by deleting the seed. An application nobody can log in to scores well
  and does not work; the harness measures the API surface and the working endpoints
  precisely so that this is not a way out.

## Database roles, while you are here

The same split applies to the database itself. The migration role may hold DDL rights and is
used once; the role the application connects with should hold `SELECT/INSERT/UPDATE/DELETE`
on its own tables and nothing else. `GRANT ALL` to the runtime role is what turns any single
injection into a dropped database.

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime;
-- and separately, used once, by the migration step only:
-- GRANT ALL PRIVILEGES ON SCHEMA public TO migrator;
```
