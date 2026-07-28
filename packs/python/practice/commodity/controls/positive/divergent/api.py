"""Positive control: the same sensitive resource reached through paths guarded differently.

`practice/divergent-resource-access` must fire on `export_customers`. Two handlers return
Customer; one requires identity and one does not. The forgotten second path is the
vulnerability -- an IDOR shipped through /export in this project's other study while the
primary read path was correctly guarded.
"""
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/customers")


@router.get("/", response_model=list[Customer])
async def list_customers(user: User = Depends(get_current_user)):
    return db.query(Customer).filter(Customer.owner_id == user.id).all()


@router.get("/export")
async def export_customers():
    """No guard, same resource. This is the finding."""
    return csv_of(db.query(Customer).all())
