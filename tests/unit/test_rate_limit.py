import time
from unittest.mock import patch

from app.core.rate_limit import FixedWindowRateLimiter


def test_allows_up_to_max_requests_then_rate_limits():
    limiter = FixedWindowRateLimiter(max_requests=3, window_seconds=60)

    assert limiter.allow("user-a") is True
    assert limiter.allow("user-a") is True
    assert limiter.allow("user-a") is True
    # Fourth request in the same window is rate limited.
    assert limiter.allow("user-a") is False
    assert limiter.allow("user-a") is False

    # A different key is independent.
    assert limiter.allow("user-b") is True


def test_window_expires_and_requests_are_allowed_again():
    limiter = FixedWindowRateLimiter(max_requests=2, window_seconds=1)

    assert limiter.allow("user-a") is True
    assert limiter.allow("user-a") is True
    assert limiter.allow("user-a") is False

    with patch("app.core.rate_limit.time.time", return_value=time.time() + 2):
        assert limiter.allow("user-a") is True


def test_remaining_counts_down():
    limiter = FixedWindowRateLimiter(max_requests=3, window_seconds=60)
    assert limiter.remaining("user-a") == 3
    limiter.allow("user-a")
    assert limiter.remaining("user-a") == 2
    limiter.allow("user-a")
    limiter.allow("user-a")
    assert limiter.remaining("user-a") == 0


def test_reset_clears_all_keys():
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60)
    limiter.allow("user-a")
    assert limiter.allow("user-a") is False

    limiter.reset()
    assert limiter.allow("user-a") is True
