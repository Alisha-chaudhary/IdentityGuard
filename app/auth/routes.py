from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db
from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.auth.service import AuthenticationError, authenticate
from app.core.rate_limit import login_rate_limiter
from app.core.security import (
    WeakPasswordError,
    check_password_strength,
    hash_password,
    verify_password,
)
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
    request: Request,
    login_request: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    # Per-IP login rate limit, checked before authentication so a burst of
    # invalid attempts cannot exhaust the application or aid enumeration.
    client_ip = request.client.host if request.client else "unknown"
    if not login_rate_limiter.check(client_ip):
        record_event(
            db,
            actor=login_request.username,
            event_type=EventType.ACCESS_DENIED,
            target=f"ip:{client_ip}",
            action="login",
            result=Result.FAILURE,
            reason="Login rate limit exceeded",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
        )

    try:
        token = authenticate(
            db,
            login_request.username,
            login_request.password,
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


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Let an authenticated user change their own password (policy enforced)."""
    if not verify_password(request.current_password, current_user.password_hash or ""):
        record_event(
            db,
            actor=current_user.username,
            event_type=EventType.USER_UPDATED,
            target=f"user:{current_user.username}",
            action="change_password",
            result=Result.DENIED,
            reason="Current password was incorrect",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current password is incorrect",
        )

    try:
        check_password_strength(request.new_password, current_user.username)
    except WeakPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    if verify_password(request.new_password, current_user.password_hash or ""):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="New password must differ from the current password",
        )

    current_user.password_hash = hash_password(request.new_password)
    record_event(
        db,
        actor=current_user.username,
        event_type=EventType.USER_UPDATED,
        target=f"user:{current_user.username}",
        action="change_password",
        result=Result.SUCCESS,
        reason="User changed their own password",
    )
    db.commit()
