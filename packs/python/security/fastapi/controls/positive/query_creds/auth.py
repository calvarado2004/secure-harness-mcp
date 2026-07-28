
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/auth")


@router.post("/login")
def login(username: str, password: str, db=Depends(get_db)):
    """Both credentials are scalar, unmarked and not in the path: query parameters."""
    return {"token": issue(username, password)}
