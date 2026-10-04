from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission
from app.db.models import User


router = APIRouter(prefix="/users", tags=["users"])


@router.get("")
def list_users(
    current_user: User = Depends(
        require_permission("IdentityGuard:user.read")
    ),
    db: Session = Depends(get_db),
) -> list[dict]:
    users = db.scalars(
        select(User).order_by(User.id)
    ).all()

    return [
        {
            "id": user.id,
            "employee_id": user.employee_id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "department_id": user.department_id,
            "status": user.status,
        }
        for user in users
    ]