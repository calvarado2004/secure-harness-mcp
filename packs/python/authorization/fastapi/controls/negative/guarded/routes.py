"""Negative control, paired to the suppressions in the authorization lane.

Each handler here is the CORRECT version of a defect in the positive control. If a rule
fires on this file it has widened past what it can justify, and the practitioner will learn
to ignore the lane -- which is how a rule set dies.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/auth")


class CustomerCreate(BaseModel):
    """No privilege field: the client cannot choose what it is allowed to be."""
    first_name: str
    email: str


@router.post("/login")
async def login(payload: CustomerCreate):
    """A declared public route. `public_routes` is why this is silence and not a finding:
    a lane that cannot be told this flags the login endpoint for not requiring a login."""
    return {"token": issue_token(payload.email)}


@router.get("/me", response_model=Customer)
async def me(user: User = Depends(get_current_user)):
    """Authenticated AND the principal is used -- scoping by the caller's own id is
    ownership authorization, and flagging it would be wrong."""
    return db.query(Customer).filter(Customer.owner_id == user.id).one()


@router.put("/{customer_id}")
async def update(customer_id: int, user: User = Depends(require_admin)):
    """A write that makes a decision about who the caller is."""
    if user.role != "admin":
        raise HTTPException(status_code=403)
    return db.update(Customer, customer_id)
