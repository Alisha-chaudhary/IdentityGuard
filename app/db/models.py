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

    users: Mapped[list[User]] = relationship(
        back_populates="department"
    )


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED', 'LOCKED', 'TERMINATED')",
            name="ck_users_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[str] = mapped_column(
        String(20),
        unique=True,
    )
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
    )
    full_name: Mapped[str] = mapped_column(
        String(150)
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
    )
    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="ACTIVE",
    )
    failed_attempts: Mapped[int] = mapped_column(
        default=0
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
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
    )
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

class AccessReviewCycle(Base):
    __tablename__ = "access_review_cycles"

    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'COMPLETED')",
            name="ck_access_review_cycles_status",
        ),
        Index(
            "ix_access_review_cycles_status",
            "status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(
        String(150),
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default="OPEN",
    )

    created_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    created_by: Mapped[User] = relationship(
        foreign_keys=[created_by_id],
    )

    items: Mapped[list[AccessReviewItem]] = relationship(
        back_populates="cycle",
        order_by="AccessReviewItem.id",
    )


class AccessReviewItem(Base):
    __tablename__ = "access_review_items"

    __table_args__ = (
        CheckConstraint(
            "decision IN ('PENDING', 'RETAIN', 'REVOKE')",
            name="ck_access_review_items_decision",
        ),
        UniqueConstraint(
            "cycle_id",
            "user_id",
            "role_id",
            name="uq_access_review_item_assignment",
        ),
        Index(
            "ix_access_review_items_cycle",
            "cycle_id",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    cycle_id: Mapped[int] = mapped_column(
        ForeignKey("access_review_cycles.id"),
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
    )

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id"),
    )

    assignment_assigned_at: Mapped[datetime] = mapped_column(
        DateTime,
    )

    decision: Mapped[str] = mapped_column(
        String(20),
        default="PENDING",
    )

    reviewer_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        default=None,
    )

    decision_reason: Mapped[str | None] = mapped_column(
        String(500),
        default=None,
    )

    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    cycle: Mapped[AccessReviewCycle] = relationship(
        back_populates="items",
    )

    user: Mapped[User] = relationship(
        foreign_keys=[user_id],
    )

    role: Mapped[Role] = relationship()

    reviewer: Mapped[User | None] = relationship(
        foreign_keys=[reviewer_id],
    )

class AccessRequest(Base):
    __tablename__ = "access_requests"

    __table_args__ = (
        CheckConstraint(
            "status IN ('REQUESTED', 'APPROVED', 'REJECTED', 'PROVISIONED')",
            name="ck_access_requests_status",
        ),
        Index(
            "ix_access_requests_requester",
            "requester_id",
        ),
        Index(
            "ix_access_requests_target_user",
            "target_user_id",
        ),
        Index(
            "ix_access_requests_status",
            "status",
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    requester_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    target_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id")
    )

    justification: Mapped[str] = mapped_column(
        String(500)
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default="REQUESTED",
    )

    decision_by: Mapped[str | None] = mapped_column(
        String(100),
        default=None,
    )

    decision_reason: Mapped[str | None] = mapped_column(
        String(500),
        default=None,
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow,
    )

    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    provisioned_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        default=None,
    )

    requester: Mapped[User] = relationship(
        foreign_keys=[requester_id]
    )

    target_user: Mapped[User] = relationship(
        foreign_keys=[target_user_id]
    )

    role: Mapped[Role] = relationship()


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
        Index(
            "ix_audit_correlation",
            "correlation_id",
        ),
        Index(
            "ix_audit_event_type",
            "event_type",
        ),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime
    )  # naive UTC

    actor: Mapped[str] = mapped_column(
        String(100)
    )

    event_type: Mapped[str] = mapped_column(
        String(50)
    )

    target: Mapped[str] = mapped_column(
        String(200)
    )

    action: Mapped[str] = mapped_column(
        String(100)
    )

    result: Mapped[str] = mapped_column(
        String(10)
    )

    reason: Mapped[str] = mapped_column(
        String(500),
        default="",
    )

    correlation_id: Mapped[str] = mapped_column(
        String(64)
    )

    prev_hash: Mapped[str] = mapped_column(
        String(64)
    )

    event_hash: Mapped[str] = mapped_column(
        String(64)
    )


for _name, _op in (
    ("update", "UPDATE"),
    ("delete", "DELETE"),
):
    event.listen(
        AuditEvent.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER IF NOT EXISTS audit_events_no_{_name} "
            f"BEFORE {_op} ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
        ).execute_if(dialect="sqlite"),
    )


class ExternalIdentity(Base):
    """Links a directory identity to a local IdentityGuard user.

    Used by LDAP synchronization to match directory entries to application
    users without relying on mutable attributes like display name or email.
    """

    __tablename__ = "external_identities"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(50), default="ldap")
    external_id: Mapped[str] = mapped_column(
        String(255),
    )  # Immutable directory identifier (e.g. LDAP entryUUID)
    local_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    dn: Mapped[str | None] = mapped_column(String(500), default=None)
    username: Mapped[str | None] = mapped_column(String(100), default=None)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=None
    )
    sync_status: Mapped[str] = mapped_column(
        String(20), default="matched"
    )  # matched / unmatched / conflict / disabled
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    __table_args__ = (
        UniqueConstraint(
            "provider", "external_id", name="uq_external_identity_provider_external_id"
        ),
        Index("ix_external_identity_local_user", "local_user_id"),
    )

    local_user: Mapped[User] = relationship(foreign_keys=[local_user_id])


class DirectoryGroupMapping(Base):
    """Explicit, configurable mapping from an LDAP group to a local role.

    Only non-privileged roles may be mapped. Unknown or unmapped groups
    grant no IdentityGuard roles. Privileged role assignments continue
    through IdentityGuard's authorization and governance controls.
    """

    __tablename__ = "directory_group_mappings"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(50), default="ldap")
    group_dn: Mapped[str] = mapped_column(String(500))
    group_name: Mapped[str] = mapped_column(String(100))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[str | None] = mapped_column(String(100), default=None)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    __table_args__ = (
        UniqueConstraint(
            "provider", "group_dn", name="uq_directory_group_mapping_provider_group_dn"
        ),
        Index("ix_directory_group_mapping_role", "role_id"),
    )

    role: Mapped[Role] = relationship()


class DirectorySyncRun(Base):
    """One row per LDAP synchronization execution.

    Records the run's mode (dry-run/apply), timing, outcome, and summary
    so failed or incomplete runs can be diagnosed.
    """

    __tablename__ = "directory_sync_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True)
    mode: Mapped[str] = mapped_column(
        String(10)
    )  # "dry-run" or "apply"
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    outcome: Mapped[str] = mapped_column(
        String(20)
    )  # completed / partial / failed
    summary: Mapped[str | None] = mapped_column(String(1000), default=None)
    error: Mapped[str | None] = mapped_column(String(1000), default=None)

    changes: Mapped[list["DirectorySyncChange"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class DirectorySyncChange(Base):
    """One proposed or applied change from a synchronization run.

    Keeps a clear distinction between proposed, applied, skipped, and failed
    changes so each sync run is auditable and idempotent.
    """

    __tablename__ = "directory_sync_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("directory_sync_runs.run_id")
    )
    change_type: Mapped[str] = mapped_column(
        String(30)
    )  # create_user / assign_role / remove_role / skip_noop / skip_conflict / skip_disabled / skip_missing
    external_id: Mapped[str | None] = mapped_column(String(255), default=None)
    local_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), default=None
    )
    target_role_id: Mapped[int | None] = mapped_column(
        ForeignKey("roles.id"), default=None
    )
    previous_state: Mapped[str | None] = mapped_column(String(1000), default=None)
    proposed_state: Mapped[str | None] = mapped_column(String(1000), default=None)
    outcome: Mapped[str] = mapped_column(
        String(20)
    )  # proposed / applied / skipped / failed
    reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_directory_sync_change_run", "run_id"),
        Index("ix_directory_sync_change_outcome", "outcome"),
    )

    run: Mapped["DirectorySyncRun"] = relationship(back_populates="changes")
    local_user: Mapped[User | None] = relationship(foreign_keys=[local_user_id])
    target_role: Mapped[Role | None] = relationship()