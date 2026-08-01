"""The same defect in the shape a single-file application ships it.

Two things differ from `seed_data.py` beside it, and each on its own was enough to make the
rule silent before: the bootstrap is a FUNCTION rather than a file, and the account is
created by a parameterised INSERT rather than by an ORM constructor. Neither difference is
about privilege, so neither should change the verdict.
"""
import sqlite3

from werkzeug.security import generate_password_hash

app = object()


def init_db():
    """Initialise the schema and seed the administrator."""
    db = sqlite3.connect("app.db")
    db.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL)""")
    existing = db.execute("SELECT 1 FROM users WHERE username = ?", ("admin",)).fetchone()
    if not existing:
        hashed_password = generate_password_hash("admin123")
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                   ("admin", hashed_password, "admin"))
    db.commit()
