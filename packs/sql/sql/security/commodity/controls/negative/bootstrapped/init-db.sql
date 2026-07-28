
-- A migration role with DDL rights, used once, is the RECOMMENDED shape and must be silent.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_runtime;
-- A bootstrap row with no usable credential: the account exists, the password is set out
-- of band. This is the fix the rule asks for.
INSERT INTO users (username, hashed_password, role) VALUES
  ('admin', NULL, 'admin');
-- An unprivileged demo row is not this rule's concern.
INSERT INTO users (username, hashed_password, role) VALUES
  ('demo', 'x', 'user');
