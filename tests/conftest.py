"""Shared test helpers."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest


class FakeClock:
    """A clock the tests control, so lockouts and expiry can be tested
    without waiting."""

    def __init__(self, start: datetime = datetime(2026, 10, 15, 9, 0)) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        """Move time forward, e.g. clock.advance(minutes=15)."""
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fast_hasher():
    """Real hashing with far fewer rounds, so the tests run quickly.
    Never use this few rounds outside tests."""
    from auth import PBKDF2Hasher

    return PBKDF2Hasher(iterations=1_000)


@pytest.fixture
def db():
    """A fresh database in memory for each test. Nothing is written to disk."""
    from auth import Database

    database = Database()
    yield database
    database.close()
