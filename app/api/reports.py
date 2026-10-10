from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import User
from app.reports.identity_inventory import get_identity_inventory


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


class IdentityInventoryItemResponse(BaseModel):
    user_id: int
    employee_id: str
    username: str
    full_name: str
    department: str
    manager_id: int | None
    status: str
    created_at: datetime
    terminated_at: datetime | None
    role_assignment_count: int


class IdentityInventoryResponse(BaseModel):
    total_count: int
    items: list[IdentityInventoryItemResponse]


@router.get(
    "/identity-inventory",
    response_model=IdentityInventoryResponse,
)
def identity_inventory_report(
    current_user: User = Depends(
        require_permission("IdentityGuard:reports.read")
    ),
    db: Session = Depends(get_db),
) -> dict:
    return get_identity_inventory(db)
