
import os

from auth import hash_password
from models import User


def seed(db):
    """The bootstrap account is still created -- that is legitimate and necessary -- but
    its password comes from the environment and seeding refuses to proceed without it."""
    pw = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    admin = User(username="admin", email="a@example.com",
                 hashed_password=hash_password(pw), role="admin")
    db.add(admin)

    # An ordinary, unprivileged demo row with a literal password is not this rule's concern:
    # it grants nothing.
    demo = User(username="demo", email="d@example.com",
                hashed_password=hash_password("demo1234"), role="user")
    db.add(demo)
