from datetime import datetime

from app.core.clock import FrozenClock, now, set_clock


def test_frozen_clock_returns_fixed_time():
    frozen_time = datetime(2026, 10, 4, 10, 0, 0)
    clock = FrozenClock(frozen_time)

    set_clock(clock)

    assert now() == frozen_time


def test_frozen_clock_can_advance():
    first_time = datetime(2026, 10, 4, 10, 0, 0)
    second_time = datetime(2026, 10, 4, 11, 0, 0)

    clock = FrozenClock(first_time)
    set_clock(clock)

    assert now() == first_time

    clock.set(second_time)

    assert now() == second_time