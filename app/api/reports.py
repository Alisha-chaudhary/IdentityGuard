from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import User
from app.reports.identity_inventory import get_identity_inventory

from app.reports.pam_activity import get_pam_activity_report


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

class PamSessionActivityResponse(BaseModel):
    session_id: int
    status: str
    started_at: datetime
    ended_at: datetime | None
    source_ip: str | None
    session_reference: str | None


class PamActivityItemResponse(BaseModel):
    request_id: int
    requester_username: str
    account_name: str
    system_name: str
    safe_name: str
    justification: str
    requested_duration_minutes: int
    request_status: str
    requested_at: datetime
    approver_id: int | None
    decision_reason: str | None
    decided_at: datetime | None
    checkout_id: int | None
    checkout_status: str | None
    checked_out_at: datetime | None
    expires_at: datetime | None
    checkout_ended_at: datetime | None
    sessions: list[PamSessionActivityResponse]


class PamActivityReportResponse(BaseModel):
    total_count: int
    items: list[PamActivityItemResponse]

@router.get(
    "/pam-activity",
    response_model=PamActivityReportResponse,
)
def pam_activity_report(
    current_user: User = Depends(
        require_permission("IdentityGuard:reports.read")
    ),
    db: Session = Depends(get_db),
) -> dict:
    return get_pam_activity_report(db)
