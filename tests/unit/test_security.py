import time

import jwt
import pytest

from app.core.security import (
    InvalidTokenError,
    WeakPasswordError,
    check_password_strength,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_hash_round_trip():
    password = "StrongPassword!2026"

    password_hash = hash_password(password)

    assert password_hash != password
    assert verify_password(password, password_hash) is True
    assert verify_password("WrongPassword!2026", password_hash) is False


def test_weak_password_is_rejected():
    with pytest.raises(WeakPasswordError):
        check_password_strength("weak")


def test_password_containing_username_is_rejected():
    with pytest.raises(WeakPasswordError):
        check_password_strength(
            "AlishaStrongPassword!2026",
            username="alisha",
        )


def test_access_token_round_trip():
    token = create_access_token("alisha.c")

    assert decode_access_token(token) == "alisha.c"


def test_tampered_token_is_rejected():
    token = create_access_token("alisha.c")
    tampered_token = token[:-1] + ("A" if token[-1] != "A" else "B")

    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered_token)


def test_expired_token_is_rejected():
    token = create_access_token("alisha.c", minutes=-1)

    with pytest.raises(InvalidTokenError):
        decode_access_token(token)