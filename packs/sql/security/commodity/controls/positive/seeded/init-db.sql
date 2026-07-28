
CREATE ROLE app_runtime WITH LOGIN PASSWORD 'app_pass';
CREATE ROLE migrator WITH LOGIN SUPERUSER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_runtime;
INSERT INTO users (username, hashed_password, role) VALUES
  ('admin', '$2b$12$abcdefghijklmnopqrstuv', 'admin');
