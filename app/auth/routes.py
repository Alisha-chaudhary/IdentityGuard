from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db
from app.auth.service import AuthenticationError, authenticate
from app.db.models import User

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
) -> dict:
    return {
        "username": current_user.username,
        "employee_id": current_user.employee_id,
        "department_id": current_user.department_id,
        "status": current_user.status,
    }