from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import new_correlation_id, record_event
from app.core.security import create_access_token, verify_password
from app.db.models import User


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Used when the username does not exist.
# We still perform an Argon2 verification so the timing is less
# dependent on whether the username exists.
_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$5xn/1Y9F/w0mvSTYEKjc/g$YAhUJ0qiKm7DozBpOOz0Tfla3EDfgUg8ddmSCQ+oerA"
)


class AuthenticationError(Exception):
    """Raised when authentication should fail with a generic message."""
    

def _utcnow() -> datetime:
    """Return naive UTC time for SQLite DateTime comparisons."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _record_login_failure(
    db: Session,
    username: str,
    reason: str,
    correlation_id: str,
) -> None:
    record_event(
        db,
        actor=username,
        event_type=EventType.LOGIN_FAILED,
        target=f"user:{username}",
        action="login",
        result=Result.FAILURE,
        reason=reason,
        correlation_id=correlation_id,
    )


def authenticate(
    db: Session,
    username: str,
    password: str,
) -> str:
    """
    Authenticate a user and return a JWT access token.

    All authentication failures raise AuthenticationError with
    the same generic message. Detailed reasons are written to
    the audit log.
    """
    correlation_id = new_correlation_id()

    user = db.scalar(
        select(User).where(User.username == username)
    )

    # Unknown user: perform a dummy Argon2 verification to reduce
    # username-enumeration timing differences.
    if user is None:
        verify_password(password, _DUMMY_PASSWORD_HASH)

        _record_login_failure(
            db,
            username,
            "Unknown username",
            correlation_id,
        )
        db.commit()

        raise AuthenticationError("Invalid credentials")

    # Disabled or terminated accounts cannot authenticate.
    if user.status in {"DISABLED", "TERMINATED"}:
        _record_login_failure(
            db,
            username,
            f"Account status is {user.status}",
            correlation_id,
        )
        db.commit()

        raise AuthenticationError("Invalid credentials")

    now = _utcnow()

    # A locked account is refused while the lock period is active.
    if user.status == "LOCKED":
        if user.locked_until is not None and user.locked_until > now:
            _record_login_failure(
                db,
                username,
                "Account is locked",
                correlation_id,
            )
            db.commit()

            raise AuthenticationError("Invalid credentials")

        # Lock period has expired, so allow a fresh attempt.
        user.status = "ACTIVE"
        user.failed_attempts = 0
        user.locked_until = None

    # Verify the supplied password.
    if not verify_password(password, user.password_hash or ""):
        user.failed_attempts += 1

        _record_login_failure(
            db,
            username,
            "Invalid password",
            correlation_id,
        )

        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.status = "LOCKED"
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)

            record_event(
                db,
                actor=username,
                event_type=EventType.ACCOUNT_LOCKED,
                target=f"user:{username}",
                action="lock_account",
                result=Result.SUCCESS,
                reason=f"Exceeded {MAX_FAILED_ATTEMPTS} failed login attempts",
                correlation_id=correlation_id,
            )

        db.commit()
        raise AuthenticationError("Invalid credentials")

    # Successful authentication resets the failed-attempt counter.
    user.failed_attempts = 0
    user.locked_until = None
    user.status = "ACTIVE"

    record_event(
        db,
        actor=username,
        event_type=EventType.LOGIN_SUCCEEDED,
        target=f"user:{username}",
        action="login",
        result=Result.SUCCESS,
        reason="Valid credentials",
        correlation_id=correlation_id,
    )

    db.commit()

    return create_access_token(user.username)