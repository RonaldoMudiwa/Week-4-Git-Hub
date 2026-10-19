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


STRONG = "Purple-Hibiscus-2003"


@pytest.fixture
def service(db, clock, fast_hasher):
    from auth import AuthService

    return AuthService.open(db, hasher=fast_hasher, clock=clock)


@pytest.fixture
def ronaldo(service):
    """A registered user: ronaldo / ronaldo@example.com with password STRONG."""
    return service.register("Ronaldo", "ronaldo@example.com", STRONG)


@pytest.fixture
def sessions(db, clock):
    from auth import SessionManager

    return SessionManager.open(db, clock=clock)


@pytest.fixture
def team(service):
    """ronaldo (1) is admin because he signed up first. amara (2) and tendai (3) are plain users."""
    service.register("ronaldo", "ronaldo@example.com", STRONG)
    service.register("amara", "amara@example.com", STRONG)
    service.register("tendai", "tendai@example.com", STRONG)
    return service


@pytest.fixture
def admin(db, clock):
    from auth import AdminService

    return AdminService.open(db, clock)
