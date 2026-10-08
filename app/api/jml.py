from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import User
from app.iam.jml import (
    DepartmentNotFoundError,
    InvalidManagerError,
    ManagerNotFoundError,
    UserAlreadyExistsError,
    UserNotFoundError,
    create_user,
    move_user,
    terminate_user,
)


router = APIRouter(
    prefix="/jml",
    tags=["JML"],
)


class CreateUserRequest(BaseModel):
    employee_id: str = Field(min_length=1, max_length=20)
    username: str = Field(min_length=1, max_length=50)
    full_name: str = Field(min_length=1, max_length=150)
    email: str = Field(min_length=3, max_length=255)
    department_id: int
    password: str = Field(min_length=12)
    manager_id: int | None = None


class MoveUserRequest(BaseModel):
    department_id: int | None = None
    manager_id: int | None = None


class UserResponse(BaseModel):
    id: int
    employee_id: str
    username: str
    full_name: str
    email: str
    department_id: int
    manager_id: int | None
    status: str
    terminated_at: object | None = None


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_jml_user(
    request: CreateUserRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:user.create")
    ),
    db: Session = Depends(get_db),
) -> User:
    try:
        user = create_user(
            db,
            employee_id=request.employee_id,
            username=request.username,
            full_name=request.full_name,
            email=request.email,
            department_id=request.department_id,
            password=request.password,
            manager_id=request.manager_id,
            actor=current_user.username,
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except DepartmentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except ManagerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    return user


@router.patch(
    "/users/{user_id}/move",
    response_model=UserResponse,
)
def move_jml_user(
    user_id: int,
    request: MoveUserRequest,
    current_user: User = Depends(
        require_permission("IdentityGuard:user.create")
    ),
    db: Session = Depends(get_db),
) -> User:
    if (
        request.department_id is None
        and request.manager_id is None
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one mover field must be provided",
        )

    try:
        user = move_user(
            db,
            user_id=user_id,
            department_id=request.department_id,
            manager_id=request.manager_id,
            actor=current_user.username,
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except DepartmentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except ManagerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except InvalidManagerError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return user


@router.post(
    "/users/{user_id}/terminate",
    response_model=UserResponse,
)
def terminate_jml_user(
    user_id: int,
    current_user: User = Depends(
        require_permission("IdentityGuard:user.create")
    ),
    db: Session = Depends(get_db),
) -> User:
    try:
        user = terminate_user(
            db,
            user_id=user_id,
            actor=current_user.username,
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    return user