from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db
from app.auth.service import AuthenticationError, authenticate
from app.db.models import User, UserRole
from app.authz.service import get_active_permissions

router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    try:
        token = authenticate(
            db,
            request.username,
            request.password,
        )
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    return LoginResponse(access_token=token)

@router.get("/me")
def get_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    active_roles = [
        assignment.role.name
        for assignment in current_user.user_roles
        if assignment.expires_at is None
        or assignment.expires_at > now
    ]

    return {
        "username": current_user.username,
        "full_name": current_user.full_name,
        "employee_id": current_user.employee_id,
        "department_id": current_user.department_id,
        "status": current_user.status,
        "roles": active_roles,
        "permissions": sorted(get_active_permissions(db, current_user)),
    }