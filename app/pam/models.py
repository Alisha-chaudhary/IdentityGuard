from __future__ import annotations

from app.db.models import User
from datetime import datetime, timezone
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def pam_utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


class PamSafe(Base):
    __tablename__ = "pam_safes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=pam_utcnow
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_pam_safes_status",
        ),
    )

    accounts: Mapped[list[PamAccount]] = relationship(
        back_populates="safe"
    )


class PamAccount(Base):
    __tablename__ = "pam_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    safe_id: Mapped[int] = mapped_column(ForeignKey("pam_safes.id"))
    name: Mapped[str] = mapped_column(String(100))
    system_name: Mapped[str] = mapped_column(String(150))
    account_type: Mapped[str] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=pam_utcnow
    )

    __table_args__ = (
        UniqueConstraint(
            "safe_id",
            "name",
            name="uq_pam_account_safe_name",
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_pam_accounts_status",
        ),
        Index("ix_pam_accounts_safe", "safe_id"),
    )

    safe: Mapped[PamSafe] = relationship(back_populates="accounts")


class PamAccessRequest(Base):
    __tablename__ = "pam_access_requests"

    __table_args__ = (
        CheckConstraint(
            "status IN ('REQUESTED', 'APPROVED', 'REJECTED', 'CANCELLED')",
            name="ck_pam_access_requests_status",
        ),
        Index("ix_pam_access_requests_requester", "requester_id"),
        Index("ix_pam_access_requests_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    requester_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    account_id: Mapped[int] = mapped_column(ForeignKey("pam_accounts.id"))
    justification: Mapped[str] = mapped_column(String(500))
    requested_duration_minutes: Mapped[int]
    status: Mapped[str] = mapped_column(String(20), default="REQUESTED")
    approver_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), default=None
    )
    decision_reason: Mapped[str | None] = mapped_column(
        String(500), default=None
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=pam_utcnow
    )
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    approver: Mapped[User | None] = relationship(foreign_keys=[approver_id])
    account: Mapped[PamAccount] = relationship()
    checkout: Mapped[PamCheckout | None] = relationship(
        back_populates="access_request",
        uselist=False,
    )


class PamCheckout(Base):
    __tablename__ = "pam_checkouts"

    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'ENDED')",
            name="ck_pam_checkouts_status",
        ),
        CheckConstraint(
            "expires_at > checked_out_at",
            name="ck_pam_checkout_expiry",
        ),
        UniqueConstraint(
            "access_request_id",
            name="uq_pam_checkout_access_request",
        ),
        Index("ix_pam_checkouts_status_expiry", "status", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    access_request_id: Mapped[int] = mapped_column(
        ForeignKey("pam_access_requests.id")
    )
    checked_out_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    checked_out_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=pam_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")

    access_request: Mapped[PamAccessRequest] = relationship(
        back_populates="checkout"
    )
    checked_out_by: Mapped[User] = relationship()


class PamSession(Base):
    __tablename__ = "pam_sessions"

    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'ENDED', 'EXPIRED', 'REVOKED')",
            name="ck_pam_sessions_status",
        ),
        Index("ix_pam_sessions_checkout", "checkout_id"),
        Index("ix_pam_sessions_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    checkout_id: Mapped[int] = mapped_column(ForeignKey("pam_checkouts.id"))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=pam_utcnow
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    source_ip: Mapped[str | None] = mapped_column(
        String(45), default=None
    )
    session_reference: Mapped[str | None] = mapped_column(
        String(100), default=None
    )

    checkout: Mapped[PamCheckout] = relationship()