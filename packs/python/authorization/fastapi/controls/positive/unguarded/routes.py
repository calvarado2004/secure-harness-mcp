"""Positive control for the FastAPI authorization lane.

Every rule this pack declares must fire on this file. If one stops firing, the lane broke
and the repository's silence stops meaning anything. These four defects are the ones the
commodity engines report as ZERO findings on the real subject, which is the whole reason
this pack exists.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/customers")

# authz/shipped-default-credential: a working default baked into the source
SECRET_KEY = "change-me-in-production-use-env-var"


class UserCreate(BaseModel):
    """authz/client-settable-privilege: the caller chooses their own role (this is E5)."""
    email: str
    password: str
    role: str = "user"


@router.get("/", response_model=list[Customer])
async def list_customers():
    """authz/unauthenticated-data-access: the whole customer table, to anyone."""
    return db.query(Customer).all()


@router.delete("/{customer_id}")
async def delete_customer(customer_id: int, _: User = Depends(get_current_user)):
    """authz/authenticated-but-unauthorized: logged in is not the same as allowed.

    The underscore is the tell: the principal is required and then discarded, so this
    asserts only that somebody is logged in -- any self-registered account can delete
    any customer.
    """
    db.delete(db.get(Customer, customer_id))
    return {"ok": True}
