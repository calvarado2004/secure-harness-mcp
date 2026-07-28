
from auth import hash_password
from models import User


def seed(db):
    admin = User(username="admin", email="a@example.com",
                 hashed_password=hash_password("admin123"), role="admin")
    db.add(admin)
