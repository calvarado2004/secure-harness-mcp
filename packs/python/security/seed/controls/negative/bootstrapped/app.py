"""The single-file shapes that must stay silent.

Each of these was a candidate false positive when the lane learned to read bootstrap
functions and raw SQL, and each is something a working application is entitled to do.
"""
import os
import sqlite3

from werkzeug.security import generate_password_hash


def init_db():
    """The administrator is still seeded. Its password comes from the environment, and
    seeding refuses to proceed without one."""
    db = sqlite3.connect("app.db")
    pw = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    hashed_password = generate_password_hash(pw)
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("admin", hashed_password, "admin"))

    # An unprivileged demo row with a literal password grants nothing and is not this
    # rule's concern.
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("demo", generate_password_hash("demo1234"), "user"))

    # An INSERT that names a role and ships no credential is the fix, not the defect: the
    # account exists and cannot be logged into until an operator sets a password.
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("operator", None, "admin"))

    # Reference data has nothing to do with privilege.
    db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("theme", "default"))
    db.commit()


def initialise_cache():
    """A function whose name matches the bootstrap pattern but seeds no account."""
    token = "cache-warm-marker"
    return token
