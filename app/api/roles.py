from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_db, require_permission
from app.db.models import Permission, Role, RolePermission, User

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("")
def list_roles(
    current_user: User = Depends(
        require_permission("IdentityGuard:user.read")
    ),
    db: Session = Depends(get_db),
) -> list[dict]:
    roles = db.scalars(
        select(Role)
        .options(
            selectinload(Role.role_permissions)
            .selectinload(RolePermission.permission)
            .selectinload(Permission.resource)
        )
        .order_by(Role.id)
    ).all()

    return [
        {
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "is_privileged": role.is_privileged,
            "permissions": [
                f"{rp.permission.resource.name}:{rp.permission.action}"
                for rp in role.role_permissions
            ],
        }
        for role in roles
    ]