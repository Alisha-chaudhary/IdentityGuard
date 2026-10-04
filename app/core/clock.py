from datetime import datetime, timezone
from typing import Protocol


def _utcnow() -> datetime:
    """Return naive UTC time for SQLite DateTime compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Clock(Protocol):
    def now(self) -> datetime:
        ...


class SystemClock:
    """Production clock that returns the current UTC time."""

    def now(self) -> datetime:
        return _utcnow()


class FrozenClock:
    """Test clock whose time can be controlled explicitly."""

    def __init__(self, current_time: datetime):
        self._current_time = current_time

    def now(self) -> datetime:
        return self._current_time

    def set(self, current_time: datetime) -> None:
        self._current_time = current_time


_clock: Clock = SystemClock()


def now() -> datetime:
    """Return the current application time."""
    return _clock.now()


def set_clock(clock: Clock) -> None:
    """Replace the active application clock."""
    global _clock
    _clock = clock