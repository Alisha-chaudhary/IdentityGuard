
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import User
from app.pam.models import PamAccessRequest, PamCheckout
from app.pam.service import (
    PamAuthorizationError,
    PamNotFoundError,
    PamServiceError,
    PamValidationError,
    checkout_privileged_access,
    decide_privileged_access,
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