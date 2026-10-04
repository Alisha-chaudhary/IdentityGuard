from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DDL,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Department(Base):
    __tablename__ = "departments"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)

    users: Mapped[list[User]] = relationship(back_populates="department")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED', 'LOCKED', 'TERMINATED')",
            name="ck_users_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[str] = mapped_column(String(20), unique=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    full_name: Mapped[str] = mapped_column(String(150))
    email: Mapped[str] = mapped_column(String(255), unique=True)

    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default="ACTIVE",
    )

    failed_attempts: Mapped[int] = mapped_column(
        default=0,
    )

    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    department_id: Mapped[int] = mapped_column(
        ForeignKey("departments.id")
    )

    manager_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        default=None,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow,
    )

    terminated_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    department: Mapped[Department] = relationship(
        back_populates="users"
    )

    manager: Mapped[User | None] = relationship(
        remote_side="User.id",
        back_populates="direct_reports",
    )

    direct_reports: Mapped[list[User]] = relationship(
        back_populates="manager"
    )

    user_roles: Mapped[list[UserRole]] = relationship(
        back_populates="user"
    )


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(
        String(255),
        default="",
    )
    is_privileged: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )

    user_roles: Mapped[list[UserRole]] = relationship(
        back_populates="role"
    )

    role_permissions: Mapped[list[RolePermission]] = relationship(
        back_populates="role"
    )


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
    )
    resource_type: Mapped[str] = mapped_column(
        String(50)
    )
    description: Mapped[str] = mapped_column(
        String(255),
        default="",
    )

    permissions: Mapped[list[Permission]] = relationship(
        back_populates="resource"
    )


class Permission(Base):
    __tablename__ = "permissions"

    __table_args__ = (
        UniqueConstraint(
            "resource_id",
            "action",
            name="uq_permission",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    resource_id: Mapped[int] = mapped_column(
        ForeignKey("resources.id")
    )

    action: Mapped[str] = mapped_column(
        String(50)
    )

    resource: Mapped[Resource] = relationship(
        back_populates="permissions"
    )

    role_permissions: Mapped[list[RolePermission]] = relationship(
        back_populates="permission"
    )


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id"),
        primary_key=True,
    )

    assigned_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    user: Mapped[User] = relationship(
        back_populates="user_roles"
    )

    role: Mapped[Role] = relationship(
        back_populates="user_roles"
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id"),
        primary_key=True,
    )

    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id"),
        primary_key=True,
    )

    role: Mapped[Role] = relationship(
        back_populates="role_permissions"
    )

    permission: Mapped[Permission] = relationship(
        back_populates="role_permissions"
    )

class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "result IN ('SUCCESS', 'DENIED', 'FAILURE')",
            name="ck_audit_result",
        ),
        Index("ix_audit_correlation", "correlation_id"),
        Index("ix_audit_event_type", "event_type"),
        {"sqlite_autoincrement": True},  # ids are never reused
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime
    )  # naive UTC
    actor: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    result: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(String(500), default="")
    correlation_id: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))


# Append-only enforcement: the database itself refuses edits and deletes.
for _name, _op in (("update", "UPDATE"), ("delete", "DELETE")):
    event.listen(
        AuditEvent.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER IF NOT EXISTS audit_events_no_{_name} "
            f"BEFORE {_op} ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
        ).execute_if(dialect="sqlite"),
    )