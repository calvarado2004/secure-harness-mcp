# Authorizing a FastAPI handler: who is allowed to do what

`Depends(get_current_user)` answers "is somebody logged in". Almost every finding in this
axis is about the next question, which it does not answer: *is this particular caller
allowed to do this particular thing to this particular object?* Authentication is a fact
about the request. Authorization is a decision about the business.

The tell for the defect is a discarded principal:

```python
async def delete_customer(customer_id: int, _: User = Depends(get_current_user)):
```

The underscore says it plainly — the identity was required and thrown away, so the handler
asserts only that *somebody* is logged in. Any account that registered ten seconds ago
passes.

## 1. Write the decision once, as a dependency

Do not put `if user.role != "admin": raise HTTPException(403)` in twenty handlers. The
twenty-first will forget, and that one is the vulnerability. Put the decision in a
dependency and apply it:

```python
from fastapi import Depends, HTTPException, status

def require_role(*allowed: str):
    """Dependency factory: the caller must hold one of these roles."""
    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="insufficient privileges")
        return user
    return _dep


@router.delete("/{customer_id}")
async def delete_customer(customer_id: int,
                          user: User = Depends(require_role("admin", "manager"))):
    ...
```

The principal is now *used*, not discarded, and a new route cannot forget the check without
someone noticing there is no dependency on it.

## 2. Ownership, when the row belongs to somebody

Roles answer "may this kind of user do this". They do not answer "is this their record".
Scope the query by the caller rather than fetching first and comparing after:

```python
@router.get("/{appointment_id}")
async def get_appointment(appointment_id: int, user: User = Depends(get_current_user)):
    q = db.query(Appointment).filter(Appointment.id == appointment_id)
    if user.role not in ("staff", "admin"):
        q = q.filter(Appointment.customer_id == user.customer_id)   # scoped, not checked
    obj = q.one_or_none()
    if obj is None:
        raise HTTPException(status_code=404)      # same answer for "absent" and "not yours"
    return obj
```

Two things matter here. Scoping the **query** cannot be forgotten the way a post-fetch `if`
can. And returning **404 rather than 403** for someone else's object stops the endpoint
confirming that a given id exists — 403 tells an attacker they found a real record.

## 3. Route every path to a resource through the same helper

The defect that ships is rarely the main read path; it is the second one. An `/export`, a
`/search`, a report endpoint — added later, guarded differently. If every path to a resource
goes through one accessor, a new path inherits the rule:

```python
def visible_customers(db, user):
    q = db.query(Customer)
    return q if user.role in ("staff", "admin") else q.filter(Customer.owner_id == user.id)
```

## 4. Privilege is never a request parameter

Remove `role`, `is_admin` and friends from inbound schemas and set them server-side. A
field the client can send is a field the client chooses:

```python
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    # no `role` — registration always creates an ordinary user

user = User(**payload.model_dump(), role="user")   # server decides
```

## Getting the balance right — read this before choosing roles

**Do not require `admin` for everything.** It satisfies the rule and breaks the business: a
dealership's salespeople must create sales, service staff must move appointments, and
inventory staff must edit vehicles. A model that locks all of it behind `admin` produces an
application where nobody can do their job, and the "fix" gets reverted along with the
protection it carried.

Authorize per operation, at the least privilege that still lets the work happen:

| resource | read | create / update | delete |
|---|---|---|---|
| vehicles | public catalogue | inventory staff, manager, admin | manager, admin |
| customers | staff | staff | manager, admin |
| sales | staff (own), manager (all) | sales staff | admin |
| appointments | owner or staff | owner or staff | owner or staff |
| employees | staff | manager, admin | admin |

If the project's declared roles do not cover a case, prefer the narrower role and leave the
handler working for the people who plainly need it — a rule that stops the product working
is not a security improvement.

## What not to do

Do not delete the endpoint, and do not make it return an empty list to everyone. Both make
the finding disappear and neither is a fix; the harness measures the route surface and the
working endpoints so that removing the thing being measured is not a way through. Every
endpoint that worked before must still work for the callers entitled to it.
