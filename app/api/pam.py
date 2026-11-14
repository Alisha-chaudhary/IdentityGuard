
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, aliased, selectinload

from app.api.deps import get_db, require_permission
from app.db.models import User
from app.pam.models import (
    PamAccessRequest,
    PamAccount,
    PamCheckout,
    PamSafe,
)
from app.pam.service import (
    PamAuthorizationError,
    PamNotFoundError,
    PamServiceError,
    PamValidationError,
    checkout_privileged_access,
    decide_privileged_access,
    end_privileged_checkout,
    expire_due_checkouts,
    request_privileged_access,
    revoke_privileged_checkout,
)

router = APIRouter(
    prefix="/pam",
    tags=["Privileged Access Management"],
)


class CreatePamRequest(BaseModel):
    account_id: int
    justification: str = Field(min_length=1, max_length=500)
    duration_minutes: int = Field(ge=1, le=60)


class DecidePamRequest(BaseModel):
    decision: str
    reason: str = Field(min_length=1, max_length=500)


class RevokeCheckoutRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class PamAccessRequestResponse(BaseModel):
    id: int
    requester_id: int
    account_id: int
    justification: str
    requested_duration_minutes: int
    status: str
    approver_id: int | None
    decision_reason: str | None
    requested_at: datetime
    decided_at: datetime | None

    model_config = {"from_attributes": True}


class PamCheckoutResponse(BaseModel):
    id: int
    access_request_id: int
    checked_out_by_id: int
    checked_out_at: datetime
    expires_at: datetime
    ended_at: datetime | None
    status: str

    model_config = {"from_attributes": True}


class PamAccountSummary(BaseModel):
    id: int
    safe_id: int
    name: str
    system_name: str
    account_type: str
    description: str | None
    status: str


class PamSafeSummary(BaseModel):
    id: int
    name: str
    description: str
    status: str
    accounts: list[PamAccountSummary]


class PamRequestSummary(BaseModel):
    id: int
    requester_id: int
    requester_username: str
    account_id: int
    account_name: str
    system_name: str
    safe_name: str
    justification: str
    requested_duration_minutes: int
    status: str
    approver_id: int | None
    decision_reason: str | None
    requested_at: datetime
    decided_at: datetime | None


class PamCheckoutSummary(BaseModel):
    id: int
    access_request_id: int
    request_id: int
    requester_username: str
    account_name: str
    system_name: str
    safe_name: str
    checked_out_by_id: int
    checked_out_by: str
    checked_out_at: datetime
    expires_at: datetime
    ended_at: datetime | None
    status: str


def _map_error(error: PamServiceError) -> HTTPException:
    if isinstance(error, PamNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        )

    if isinstance(error, PamAuthorizationError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    if isinstance(error, PamValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        )

    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(error),
    )


@router.post(
    "/requests",
    response_model=PamAccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_pam_request(
    request: CreatePamRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.request")
    ),
    db: Session = Depends(get_db),
) -> PamAccessRequest:
    try:
        return request_privileged_access(
            db,
            requester_id=current_user.id,
            account_id=request.account_id,
            justification=request.justification,
            duration_minutes=request.duration_minutes,
        )
    except PamServiceError as error:
        raise _map_error(error) from error


@router.post(
    "/requests/{request_id}/decision",
    response_model=PamAccessRequestResponse,
)
def decide_pam_request(
    request_id: int,
    request: DecidePamRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.approve")
    ),
    db: Session = Depends(get_db),
) -> PamAccessRequest:
    try:
        return decide_privileged_access(
            db,
            request_id=request_id,
            approver_id=current_user.id,
            decision=request.decision,
            reason=request.reason,
        )
    except PamServiceError as error:
        raise _map_error(error) from error


@router.post(
    "/requests/{request_id}/checkout",
    response_model=PamCheckoutResponse,
    status_code=status.HTTP_201_CREATED,
)
def checkout_pam_request(
    request_id: int,
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.checkout")
    ),
    db: Session = Depends(get_db),
) -> PamCheckout:
    try:
        return checkout_privileged_access(
            db,
            request_id=request_id,
            user_id=current_user.id,
        )
    except PamServiceError as error:
        raise _map_error(error) from error


@router.post(
    "/checkouts/{checkout_id}/revoke",
    response_model=PamCheckoutResponse,
)
def revoke_pam_checkout(
    checkout_id: int,
    request: RevokeCheckoutRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.revoke")
    ),
    db: Session = Depends(get_db),
) -> PamCheckout:
    try:
        return revoke_privileged_checkout(
            db,
            checkout_id=checkout_id,
            actor_id=current_user.id,
            reason=request.reason,
        )
    except PamServiceError as error:
        raise _map_error(error) from error

@router.post(
    "/checkouts/{checkout_id}/end",
    response_model=PamCheckoutResponse,
)
def end_pam_checkout(
    checkout_id: int,
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.checkout")
    ),
    db: Session = Depends(get_db),
) -> PamCheckout:
    try:
        return end_privileged_checkout(
            db,
            checkout_id=checkout_id,
            user_id=current_user.id,
        )
    except PamServiceError as error:
        raise _map_error(error) from error


@router.post(
    "/checkouts/expire-due",
    response_model=list[PamCheckoutResponse],
)
def expire_due_pam_checkouts(
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.revoke")
    ),
    db: Session = Depends(get_db),
) -> list[PamCheckout]:
    """Run the expiry sweep now (a background task also runs it)."""
    return expire_due_checkouts(db)


@router.get(
    "/safes",
    response_model=list[PamSafeSummary],
)
def list_pam_safes(
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.request")
    ),
    db: Session = Depends(get_db),
) -> list[PamSafe]:
    """List PAM safes and their active accounts.

    Read-only: surfaces the accounts available for privileged-access
    requests. No credentials are ever returned.
    """
    safes = db.scalars(
        select(PamSafe)
        .options(
            selectinload(PamSafe.accounts)
        )
        .order_by(PamSafe.name)
    ).all()
    return safes


@router.get(
    "/requests",
    response_model=list[PamRequestSummary],
)
def list_pam_requests(
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.request")
    ),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List privileged-access requests with account, safe and requester
    context. Read-only."""
    statement = (
        select(
            PamAccessRequest,
            PamAccount,
            PamSafe,
            User.username.label("requester_username"),
        )
        .join(PamAccount, PamAccessRequest.account_id == PamAccount.id)
        .join(PamSafe, PamAccount.safe_id == PamSafe.id)
        .join(User, PamAccessRequest.requester_id == User.id)
        .order_by(PamAccessRequest.id)
    )

    rows = db.execute(statement).all()
    return [
        {
            "id": request.id,
            "requester_id": request.requester_id,
            "requester_username": requester_username,
            "account_id": account.id,
            "account_name": account.name,
            "system_name": account.system_name,
            "safe_name": safe.name,
            "justification": request.justification,
            "requested_duration_minutes": request.requested_duration_minutes,
            "status": request.status,
            "approver_id": request.approver_id,
            "decision_reason": request.decision_reason,
            "requested_at": request.requested_at,
            "decided_at": request.decided_at,
        }
        for request, account, safe, requester_username in rows
    ]


@router.get(
    "/checkouts",
    response_model=list[PamCheckoutSummary],
)
def list_pam_checkouts(
    current_user: User = Depends(
        require_permission("IdentityGuard:pam.request")
    ),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List privileged-access checkouts with request, account and safe
    context. Includes active, expired, revoked and ended checkouts.
    Read-only."""
    checkout_holder = aliased(User)

    statement = (
        select(
            PamCheckout,
            PamAccessRequest,
            PamAccount,
            PamSafe,
            User.username.label("requester_username"),
            checkout_holder.full_name.label("checked_out_by"),
        )
        .join(PamAccessRequest, PamCheckout.access_request_id == PamAccessRequest.id)
        .join(PamAccount, PamAccessRequest.account_id == PamAccount.id)
        .join(PamSafe, PamAccount.safe_id == PamSafe.id)
        .join(User, PamAccessRequest.requester_id == User.id)
        .outerjoin(
            checkout_holder,
            PamCheckout.checked_out_by_id == checkout_holder.id,
        )
        .order_by(PamCheckout.id.desc())
    )

    rows = db.execute(statement).all()
    return [
        {
            "id": checkout.id,
            "access_request_id": checkout.access_request_id,
            "request_id": checkout.access_request_id,
            "requester_username": requester_username,
            "account_name": account.name,
            "system_name": account.system_name,
            "safe_name": safe.name,
            "checked_out_by_id": checkout.checked_out_by_id,
            "checked_out_by": checked_out_by,
            "checked_out_at": checkout.checked_out_at,
            "expires_at": checkout.expires_at,
            "ended_at": checkout.ended_at,
            "status": checkout.status,
        }
        for checkout, request, account, safe, requester_username, checked_out_by in rows
    ]
