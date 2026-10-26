import time

from app.core.rate_limit import InMemoryRateLimiter


def test_allows_requests_up_to_limit():
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is False  # 4th request exceeds the limit


def test_different_ips_tracked_separately():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is False
    assert limiter.check("ip-b") is True  # a different IP is not affected


def test_window_expires_old_requests(monkeypatch):
    original_time = time.time
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is False
    monkeypatch.setattr(time, "time", lambda: original_time() + 61)
    assert limiter.check("ip-a") is True  # window has slid, allowed again


def test_reset_clears_records():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    limiter.check("ip-a")
    assert limiter.check("ip-a") is False
    limiter.reset("ip-a")
    assert limiter.check("ip-a") is True


def test_reset_all_clears_every_ip():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    limiter.check("ip-a")
    limiter.check("ip-b")
    limiter.reset()
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-b") is True
