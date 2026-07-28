
from fastapi import APIRouter, Depends, Form
from pydantic import BaseModel
router = APIRouter(prefix="/auth")


class Credentials(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(payload: Credentials, db=Depends(get_db)):
    """A model parameter is a request BODY. Silence is correct."""
    return {"token": issue(payload.username, payload.password)}


@router.post("/token")
def token(username: str = Form(...), password: str = Form(...)):
    """Form(...) is a form body, not the query string. Silence is correct."""
    return {"token": issue(username, password)}


@router.get("/users/{username}")
def profile(username: str):
    """A PATH parameter. It is in the URL by design and is not a credential binding."""
    return {"user": username}


@router.get("/search")
def search(q: str, limit: int = 20):
    """Ordinary query parameters that are not credentials. Silence is correct."""
    return {"q": q, "limit": limit}
