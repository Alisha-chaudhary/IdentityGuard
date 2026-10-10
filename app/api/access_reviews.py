
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import AccessReviewCycle, AccessReviewItem, User
from app.iam.access_reviews import (
    AccessReviewError,
    AccessReviewAlreadyCompletedError,
    AccessReviewDecisionError,
    AccessReviewInvalidError,
    AccessReviewNotFoundError,
    AccessReviewSelfReviewError,
    complete_access_review_cycle,
    create_access_review_cycle,
    record_access_review_decision,
)

router = APIRouter(
    prefix="/access-reviews",
    tags=["Access Reviews"],
)


class CreateAccessReviewRequest(BaseModel):
    name: str = Field(min_length=1, max_length=150)


class RecordReviewDecisionRequest(BaseModel):
    item_id: int
    decision: str
    reason: str = Field(min_length=1, max_length=500)


class AccessReviewItemResponse(BaseModel):
    id: int
    cycle_id: int
    user_id: int
    role_id: int
    assignment_assigned_at: datetime
    decision: str
    reviewer_id: int | None
    decision_reason: str | None
    decided_at: datetime | None

    model_config = {"from_attributes": True}


class AccessReviewCycleResponse(BaseModel):
    id: int
    name: str
    status: str
    created_by_id: int
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class AccessReviewDetailResponse(AccessReviewCycleResponse):
    items: list[AccessReviewItemResponse]


def _map_error(error: AccessReviewError) -> HTTPException:
    if isinstance(error, AccessReviewNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        )

    if isinstance(error, AccessReviewSelfReviewError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(error),
        )

    if isinstance(
        error,
        (
            AccessReviewAlreadyCompletedError,
            AccessReviewDecisionError,
        ),
    ):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    if isinstance(error, AccessReviewInvalidError):
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
    response_model=AccessReviewCycleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_review(
    request: CreateAccessReviewRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:access_review.create")
    ),
    db: Session = Depends(get_db),
) -> AccessReviewCycle:
    try:
        return create_access_review_cycle(
            db,
            creator=current_user,
            name=request.name,
        )
    except AccessReviewError as error:
        raise _map_error(error) from error


@router.get(
    "",
    response_model=list[AccessReviewCycleResponse],
)
def list_reviews(
    current_user: User = Depends(
        require_permission("IdentityGuard:access_review.view")
    ),
    db: Session = Depends(get_db),
) -> list[AccessReviewCycle]:
    return list(
        db.query(AccessReviewCycle)
        .order_by(AccessReviewCycle.created_at.desc())
        .all()
    )


@router.get(
    "/{cycle_id}",
    response_model=AccessReviewDetailResponse,
)
def get_review(
    cycle_id: int,
    current_user: User = Depends(
        require_permission("IdentityGuard:access_review.view")
    ),
    db: Session = Depends(get_db),
) -> AccessReviewCycle:
    cycle = db.get(AccessReviewCycle, cycle_id)
    if cycle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Access review cycle {cycle_id} not found",
        )
    return cycle


@router.post(
    "/{cycle_id}/decisions",
    response_model=AccessReviewItemResponse,
)
def decide_review_item(
    cycle_id: int,
    request: RecordReviewDecisionRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:access_review.decide")
    ),
    db: Session = Depends(get_db),
) -> AccessReviewItem:
    try:
        return record_access_review_decision(
            db,
            cycle_id=cycle_id,
            item_id=request.item_id,
            reviewer=current_user,
            decision=request.decision,
            reason=request.reason,
        )
    except AccessReviewError as error:
        raise _map_error(error) from error


@router.post(
    "/{cycle_id}/complete",
    response_model=AccessReviewCycleResponse,
)
def complete_review(
    cycle_id: int,
    current_user: User = Depends(
        require_permission("IdentityGuard:access_review.complete")
    ),
    db: Session = Depends(get_db),
) -> AccessReviewCycle:
    try:
        return complete_access_review_cycle(
            db,
            cycle_id=cycle_id,
            actor=current_user,
        )
    except AccessReviewError as error:
        raise _map_error(error) from error