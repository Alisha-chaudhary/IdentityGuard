from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission
from app.db.models import AccessRequest, User
from app.iam.access_requests import (
    AccessRequestAlreadyProvisionedError,
    AccessRequestAlreadyDecidedError,
    AccessRequestError,
    AccessRequestNotApprovedError,
    AccessRequestNotFoundError,
    InvalidAccessRequestError,
    RoleNotFoundError,
    SelfApprovalError,
    UserNotFoundError,
    approve_access_request,
    create_access_request,
    list_access_requests,
    provision_access_request,
    reject_access_request,
)

router = APIRouter(
    prefix="/access-requests",
    tags=["Access Requests"],
)


class CreateAccessRequest(BaseModel):
    target_user_id: int
    role_id: int
    justification: str = Field(min_length=1, max_length=500)
    expires_at: datetime | None = None


class DecisionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class AccessRequestResponse(BaseModel):
    id: int
    requester_id: int
    target_user_id: int
    role_id: int
    justification: str
    status: str
    decision_by: str | None
    decision_reason: str | None
    requested_at: datetime
    decided_at: datetime | None
    provisioned_at: datetime | None
    expires_at: datetime | None

    model_config = {"from_attributes": True}


def _map_error(error: AccessRequestError) -> HTTPException:
    if isinstance(
        error,
        (
            AccessRequestNotFoundError,
            UserNotFoundError,
            RoleNotFoundError,
        ),
    ):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        )

    if isinstance(error, SelfApprovalError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(error),
        )

    if isinstance(
        error,
        (
            AccessRequestAlreadyDecidedError,
            AccessRequestNotApprovedError,
            AccessRequestAlreadyProvisionedError,
        ),
    ):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    if isinstance(error, InvalidAccessRequestError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        )

    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(error),
    )


@router.post(
    "",
    response_model=AccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def request_access(
    request: CreateAccessRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:access.request")
    ),
    db: Session = Depends(get_db),
) -> AccessRequest:
    try:
        return create_access_request(
            db=db,
            requester_id=current_user.id,
            target_user_id=request.target_user_id,
            role_id=request.role_id,
            justification=request.justification,
            expires_at=request.expires_at,
        )
    except AccessRequestError as error:
        raise _map_error(error) from error


@router.get(
    "",
    response_model=list[AccessRequestResponse],
)
def get_access_requests(
    current_user: User = Depends(
        require_permission("IdentityGuard:access.approve")
    ),
    db: Session = Depends(get_db),
) -> list[AccessRequest]:
    return list_access_requests(db)


@router.post(
    "/{request_id}/approve",
    response_model=AccessRequestResponse,
)
def approve_request(
    request_id: int,
    decision: DecisionRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:access.approve")
    ),
    db: Session = Depends(get_db),
) -> AccessRequest:
    try:
        return approve_access_request(
            db=db,
            request_id=request_id,
            approver=current_user,
            reason=decision.reason,
        )
    except AccessRequestError as error:
        raise _map_error(error) from error


@router.post(
    "/{request_id}/reject",
    response_model=AccessRequestResponse,
)
def reject_request(
    request_id: int,
    decision: DecisionRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:access.approve")
    ),
    db: Session = Depends(get_db),
) -> AccessRequest:
    try:
        return reject_access_request(
            db=db,
            request_id=request_id,
            approver=current_user,
            reason=decision.reason,
        )
    except AccessRequestError as error:
        raise _map_error(error) from error


@router.post(
    "/{request_id}/provision",
    response_model=AccessRequestResponse,
)
def provision_request(
    request_id: int,
    current_user: User = Depends(
        require_permission("IdentityGuard:access.provision")
    ),
    db: Session = Depends(get_db),
) -> AccessRequest:
    try:
        return provision_access_request(
            db=db,
            request_id=request_id,
            provisioner=current_user,
        )
    except AccessRequestError as error:
        raise _map_error(error) from error