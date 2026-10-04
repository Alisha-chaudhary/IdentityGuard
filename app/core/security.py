import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()
_SECRET = os.environ.get("IDENTITYGUARD_JWT_SECRET") or secrets.token_urlsafe(48)
_ALGORITHM = "HS256"


class WeakPasswordError(ValueError):
    pass


class InvalidTokenError(Exception):
    pass


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def check_password_strength(password: str, username: str = "") -> None:
    problems = []
    if len(password) < 12:
        problems.append("at least 12 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if problems:
        raise WeakPasswordError("Password needs " + ", ".join(problems))


def create_access_token(subject: str, minutes: int = 15) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc
    return payload["sub"]