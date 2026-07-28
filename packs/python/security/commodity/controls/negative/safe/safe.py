"""Negative control, paired to the false-positive filters in this pack.

Every construct here was a REAL false positive from a real run, and each one is why a
specific filter exists. If a filter is tightened and one of these starts firing again, the
weighted load rises with no defect behind it -- and inflated analyzer load is precisely the
artefact this project criticises in others' work. Then it would be ours.
"""
import hashlib

from werkzeug.security import generate_password_hash

# The `nonsecret_literal` filter: scheme names and algorithm names look like secrets to a
# pattern scanner and are not. "Bearer" was a genuine bandit B105 on the dealership repo --
# the single finding the commodity engine reported on an application that was serving its
# whole customer table anonymously.
AUTH_SCHEME = "Bearer"
HASH_ALGO = "scrypt"


def hash_password(pw):
    """A slow salted KDF: the correct answer, and it must not read as a weak-hash finding."""
    return generate_password_hash(pw, method="scrypt")


def file_checksum(path):
    """A non-security checksum. usedforsecurity=False is the intended escape hatch, and
    using it is correct rather than a suppression."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read(), usedforsecurity=False).hexdigest()


def search(conn, term):
    """B608 defers to dataflow, and this is why: the query is built with a placeholder and
    the value is passed as a parameter. A pattern lane sees string concatenation next to
    SELECT and is wrong."""
    sql = "SELECT * FROM notes WHERE body LIKE ?"
    return conn.execute(sql, (f"%{term}%",))


def cleanup(handle):
    """B110 try/except/pass, defensively: closing a handle that may already be closed is
    not an error swallowed, it is an error that does not exist."""
    try:
        handle.close()
    except Exception:
        pass
