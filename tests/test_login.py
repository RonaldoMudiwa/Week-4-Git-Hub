"""Tests for signing up, logging in, lockout and changing passwords."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from auth import (
    AccountDisabledError,
    AccountLockedError,
    AuthService,
    DuplicateError,
    InvalidCredentialsError,
    LockoutPolicy,
    LoginError,
    PBKDF2Hasher,
    ValidationError,
    WeakPasswordError,
)

from .conftest import STRONG

NEW = "Half-Of-A-Yellow-Sun-2006"


class TestRegister:
    def test_register_saves_a_hash_not_the_password(self, service, ronaldo, clock):
        assert ronaldo.user_id == 1
        assert ronaldo.username == "ronaldo"
        assert STRONG not in ronaldo.password_hash
        assert service.get_user(1).created_at == clock.now

    def test_weak_password_lists_every_problem(self, service):
        with pytest.raises(WeakPasswordError) as raised:
            service.register("amara", "amara@example.com", "short")
        assert len(raised.value.problems) >= 3
        assert service.users == []

    def test_password_with_the_username_is_refused(self, service):
        with pytest.raises(WeakPasswordError, match="username"):
            service.register("amara", "amara@example.com", "Amara-Is-Great-26")

    def test_bad_username_is_reported_before_the_password(self, service):
        with pytest.raises(ValidationError, match="Username"):
            service.register("x", "amara@example.com", "weak")

    def test_taken_username_or_email(self, service, ronaldo):
        with pytest.raises(DuplicateError):
            service.register("RONALDO", "other@example.com", STRONG)
        with pytest.raises(DuplicateError):
            service.register("other", "Ronaldo@Example.com", STRONG)


class TestLogin:
    def test_with_username_or_email(self, service, ronaldo, clock):
        assert service.login("ronaldo", STRONG) == ronaldo
        assert service.login("RONALDO@example.com", STRONG) == ronaldo
        assert service.get_user(1).last_login_at == clock.now

    def test_wrong_password_and_unknown_user_say_the_same_thing(self, service, ronaldo):
        with pytest.raises(InvalidCredentialsError) as wrong_password:
            service.login("ronaldo", "Not-The-Password-1")
        with pytest.raises(InvalidCredentialsError) as no_such_user:
            service.login("nobody", "Not-The-Password-1")
        assert str(wrong_password.value) == str(no_such_user.value) == "Wrong username or password."

    def test_unknown_user_still_runs_the_hash(self, db, clock):
        class CountingHasher(PBKDF2Hasher):
            calls = 0

            def verify(self, password, stored):
                CountingHasher.calls += 1
                return super().verify(password, stored)

        service = AuthService.open(db, hasher=CountingHasher(1_000), clock=clock)
        with pytest.raises(InvalidCredentialsError):
            service.login("ghost", "anything")
        assert CountingHasher.calls == 1

    def test_failed_attempts_are_saved(self, service, ronaldo):
        for _ in range(2):
            with pytest.raises(InvalidCredentialsError):
                service.login("ronaldo", "wrong")
        assert service.get_user(1).failed_logins == 2

    def test_good_login_resets_the_count(self, service, ronaldo):
        with pytest.raises(InvalidCredentialsError):
            service.login("ronaldo", "wrong")
        service.login("ronaldo", STRONG)
        assert service.get_user(1).failed_logins == 0

    def test_every_login_problem_is_a_login_error(self, service, ronaldo):
        with pytest.raises(LoginError):
            service.login("ronaldo", "wrong")


class TestLockout:
    def lock(self, service):
        for _ in range(4):
            with pytest.raises(InvalidCredentialsError):
                service.login("ronaldo", "wrong")
        with pytest.raises(AccountLockedError, match="09:15"):
            service.login("ronaldo", "wrong")

    def test_fifth_wrong_password_locks_the_account(self, service, ronaldo):
        self.lock(service)
        assert service.get_user(1).locked_until == datetime(2026, 10, 15, 9, 15)

    def test_even_the_right_password_is_refused_while_locked(self, service, ronaldo):
        self.lock(service)
        with pytest.raises(AccountLockedError):
            service.login("ronaldo", STRONG)

    def test_lock_runs_out(self, service, ronaldo, clock):
        self.lock(service)
        clock.advance(minutes=15)
        service.login("ronaldo", STRONG)

    def test_admin_can_unlock(self, service, ronaldo, admin):
        service.register("amara", "amara@example.com", STRONG)
        for _ in range(5):
            with pytest.raises(LoginError):
                service.login("amara", "wrong")
        admin.unlock(ronaldo, 2)
        service.login("amara", STRONG)

    def test_custom_policy(self, db, clock, fast_hasher):
        service = AuthService.open(db, hasher=fast_hasher, clock=clock,
                                   lockout=LockoutPolicy(2, timedelta(hours=1)))
        service.register("amara", "amara@example.com", STRONG)
        with pytest.raises(InvalidCredentialsError):
            service.login("amara", "wrong")
        with pytest.raises(AccountLockedError, match="10:00"):
            service.login("amara", "wrong")

    @pytest.mark.parametrize("kwargs", [
        {"max_attempts": 0}, {"max_attempts": True}, {"lock_for": timedelta(0)}, {"lock_for": 15},
    ])
    def test_bad_policy(self, kwargs):
        with pytest.raises(ValidationError):
            LockoutPolicy(**kwargs)


class TestDisabledAccounts:
    def test_disabled_account_cannot_log_in(self, service, ronaldo, db):
        from auth import SQLiteUserRepository

        ronaldo.deactivate()
        SQLiteUserRepository(db).update(ronaldo)
        with pytest.raises(AccountDisabledError):
            service.login("ronaldo", STRONG)

    def test_wrong_password_on_a_disabled_account_gives_nothing_away(self, service, ronaldo, db):
        from auth import SQLiteUserRepository

        ronaldo.deactivate()
        SQLiteUserRepository(db).update(ronaldo)
        with pytest.raises(InvalidCredentialsError):
            service.login("ronaldo", "wrong")


class TestRehash:
    def test_old_hash_is_upgraded_at_login(self, db, clock):
        weak = AuthService.open(db, hasher=PBKDF2Hasher(1_000), clock=clock)
        weak.register("ronaldo", "ronaldo@example.com", STRONG)
        stronger = AuthService.open(db, hasher=PBKDF2Hasher(2_000), clock=clock)
        stronger.login("ronaldo", STRONG)
        assert stronger.get_user(1).password_hash.startswith("pbkdf2_sha256$2000$")
        stronger.login("ronaldo", STRONG)


class TestChangePassword:
    def test_change(self, service, ronaldo):
        service.change_password(1, STRONG, NEW)
        service.login("ronaldo", NEW)
        with pytest.raises(InvalidCredentialsError):
            service.login("ronaldo", STRONG)

    def test_current_password_must_be_right(self, service, ronaldo):
        with pytest.raises(InvalidCredentialsError, match="current"):
            service.change_password(1, "wrong", NEW)

    def test_new_password_follows_the_rules(self, service, ronaldo):
        with pytest.raises(WeakPasswordError):
            service.change_password(1, STRONG, "weak")
        with pytest.raises(ValidationError, match="different"):
            service.change_password(1, STRONG, STRONG)
        service.login("ronaldo", STRONG)


def test_default_settings(db):
    service = AuthService.open(db)
    assert service.now <= datetime.now()
