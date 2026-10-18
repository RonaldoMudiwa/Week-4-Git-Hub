"""Tests for login sessions."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from auth import (
    InvalidSessionError,
    Session,
    SessionError,
    SessionExpiredError,
    SessionManager,
    SessionPolicy,
    SQLiteSessionRepository,
    SQLiteUserRepository,
    User,
    ValidationError,
)
from auth.sessions import hash_token


def test_start_gives_a_long_random_token(sessions, ronaldo):
    first = sessions.start(ronaldo)
    second = sessions.start(ronaldo)
    assert len(first) >= 40
    assert first != second


def test_token_finds_the_user(sessions, ronaldo):
    assert sessions.authenticate(sessions.start(ronaldo)) == ronaldo


def test_only_a_hash_of_the_token_is_stored(sessions, ronaldo, db):
    token = sessions.start(ronaldo)
    stored = [row["token_hash"] for row in db.query("SELECT token_hash FROM sessions")]
    assert stored == [hash_token(token)]
    assert token not in stored[0]


@pytest.mark.parametrize("token", ["", None, "made-up-token", 123])
def test_bad_tokens(sessions, ronaldo, token):
    sessions.start(ronaldo)
    with pytest.raises(InvalidSessionError):
        sessions.authenticate(token)


class TestTimeouts:
    def test_idle_timeout(self, sessions, ronaldo, clock):
        token = sessions.start(ronaldo)
        clock.advance(minutes=29)
        sessions.authenticate(token)
        clock.advance(minutes=29)   # still fine, activity reset the timer
        sessions.authenticate(token)
        clock.advance(minutes=30)
        with pytest.raises(SessionExpiredError):
            sessions.authenticate(token)

    def test_maximum_age_even_when_busy(self, sessions, ronaldo, clock):
        token = sessions.start(ronaldo)
        for _ in range(47):            # active every 15 minutes for 11h 45m
            clock.advance(minutes=15)
            sessions.authenticate(token)
        clock.advance(minutes=15)      # 12 hours
        with pytest.raises(SessionExpiredError):
            sessions.authenticate(token)

    def test_custom_policy(self, db, clock, ronaldo):
        manager = SessionManager.open(db, clock=clock,
                                      policy=SessionPolicy(idle_timeout=timedelta(minutes=5)))
        token = manager.start(ronaldo)
        clock.advance(minutes=5)
        with pytest.raises(SessionExpiredError):
            manager.authenticate(token)

    @pytest.mark.parametrize("kwargs", [{"idle_timeout": timedelta(0)}, {"max_age": 60}])
    def test_bad_policy(self, kwargs):
        with pytest.raises(ValidationError):
            SessionPolicy(**kwargs)


class TestLoggingOut:
    def test_end_one_session(self, sessions, ronaldo):
        token = sessions.start(ronaldo)
        other = sessions.start(ronaldo)
        sessions.end(token)
        with pytest.raises(InvalidSessionError, match="logged out"):
            sessions.authenticate(token)
        sessions.authenticate(other)
        sessions.end(token)   # twice is harmless

    def test_end_everywhere(self, sessions, ronaldo):
        tokens = [sessions.start(ronaldo) for _ in range(3)]
        assert sessions.end_all(ronaldo.user_id) == 3
        for token in tokens:
            with pytest.raises(SessionError):
                sessions.authenticate(token)
        assert sessions.end_all(ronaldo.user_id) == 0

    def test_active_sessions(self, sessions, ronaldo, clock):
        sessions.start(ronaldo)
        clock.advance(minutes=40)
        newest = sessions.start(ronaldo)
        active = sessions.active_sessions(ronaldo.user_id)
        assert len(active) == 1
        assert active[0].token_hash == hash_token(newest)

    def test_switched_off_account_is_logged_out(self, sessions, ronaldo, db):
        token = sessions.start(ronaldo)
        ronaldo.deactivate()
        SQLiteUserRepository(db).update(ronaldo)
        with pytest.raises(InvalidSessionError, match="switched off"):
            sessions.authenticate(token)


def test_purge_old_sessions(sessions, ronaldo, clock, db):
    old = sessions.start(ronaldo)
    sessions.end(old)
    clock.advance(days=31)
    sessions.start(ronaldo)
    assert sessions.purge() == 1
    assert db.query_one("SELECT COUNT(*) FROM sessions")[0] == 1


def test_unsaved_user_cannot_have_a_session(sessions):
    user = User("ghost", "ghost@example.com", "x", datetime(2026, 10, 15))
    with pytest.raises(ValidationError):
        sessions.start(user)


def test_repository_refuses_unknown_users(db, clock):
    repo = SQLiteSessionRepository(db)
    with pytest.raises(ValidationError):
        repo.add(Session(99, "abc", clock.now, clock.now, clock.now))


def test_deleting_a_user_deletes_their_sessions(sessions, ronaldo, db):
    sessions.start(ronaldo)
    db.execute("DELETE FROM users WHERE user_id = ?", (ronaldo.user_id,))
    assert db.query_one("SELECT COUNT(*) FROM sessions")[0] == 0


def test_default_settings(db):
    manager = SessionManager.open(db)
    assert manager.active_sessions(1) == []
