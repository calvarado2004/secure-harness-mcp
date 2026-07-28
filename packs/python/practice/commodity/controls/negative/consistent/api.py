"""Negative control: every path to the resource carries the same guard.

If `practice/divergent-resource-access` fires here it is reporting consistency as
divergence, which is worse than useless -- it trains the practitioner to ignore the lane.
"""
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/customers")


@router.get("/", response_model=list[Customer])
async def list_customers(user: User = Depends(get_current_user)):
    return db.query(Customer).filter(Customer.owner_id == user.id).all()


@router.get("/export")
async def export_customers(user: User = Depends(get_current_user)):
    return csv_of(db.query(Customer).filter(Customer.owner_id == user.id).all())
