"""Tests for password reset and the audit log."""

from __future__ import annotations

from datetime import timedelta

import pytest

from auth import (
    AuditEvent,
    InvalidCredentialsError,
    InvalidSessionError,
    NullAuditLog,
    PermissionDeniedError,
    ResetToken,
    ResetTokenError,
    SQLiteAuditLog,
    SQLiteResetTokenRepository,
    ValidationError,
    WeakPasswordError,
)
from auth.sessions import hash_token

from .conftest import STRONG

NEW = "Half-Of-A-Yellow-Sun-2006"


class TestPasswordReset:
    def test_reset_with_the_token(self, service, ronaldo):
        token = service.request_password_reset("Ronaldo@Example.com")
        service.reset_password(token, NEW)
        service.login("ronaldo", NEW)
        with pytest.raises(InvalidCredentialsError):
            service.login("ronaldo", STRONG)

    def test_unknown_email_gives_no_token(self, service, ronaldo):
        assert service.request_password_reset("nobody@example.com") is None

    def test_switched_off_account_gives_no_token(self, service, ronaldo, db):
        from auth import SQLiteUserRepository

        ronaldo.deactivate()
        SQLiteUserRepository(db).update(ronaldo)
        assert service.request_password_reset("ronaldo@example.com") is None

    def test_token_works_once(self, service, ronaldo):
        token = service.request_password_reset("ronaldo@example.com")
        service.reset_password(token, NEW)
        with pytest.raises(ResetTokenError):
            service.reset_password(token, "Another-Strong-Pass-1")

    def test_token_runs_out_after_an_hour(self, service, ronaldo, clock):
        token = service.request_password_reset("ronaldo@example.com")
        clock.advance(minutes=60)
        with pytest.raises(ResetTokenError):
            service.reset_password(token, NEW)

    def test_only_the_newest_token_works(self, service, ronaldo):
        old = service.request_password_reset("ronaldo@example.com")
        new = service.request_password_reset("ronaldo@example.com")
        with pytest.raises(ResetTokenError):
            service.reset_password(old, NEW)
        service.reset_password(new, NEW)

    @pytest.mark.parametrize("token", ["", None, "made-up"])
    def test_bad_tokens_all_get_the_same_message(self, service, ronaldo, token):
        with pytest.raises(ResetTokenError, match="wrong, already used, or has run out"):
            service.reset_password(token, NEW)

    def test_weak_new_password_keeps_the_token_usable(self, service, ronaldo):
        token = service.request_password_reset("ronaldo@example.com")
        with pytest.raises(WeakPasswordError):
            service.reset_password(token, "weak")
        service.reset_password(token, NEW)

    def test_reset_unlocks_the_account(self, service, ronaldo):
        for _ in range(5):
            with pytest.raises(Exception):
                service.login("ronaldo", "wrong")
        service.reset_password(service.request_password_reset("ronaldo@example.com"), NEW)
        service.login("ronaldo", NEW)

    def test_only_a_hash_of_the_token_is_stored(self, service, ronaldo, db):
        token = service.request_password_reset("ronaldo@example.com")
        assert db.query_one("SELECT token_hash FROM reset_tokens")[0] == hash_token(token)

    def test_repository_refuses_unknown_users(self, db, clock):
        with pytest.raises(ValidationError):
            SQLiteResetTokenRepository(db).add(ResetToken(9, "x", clock.now, clock.now))


class TestPasswordChangesLogOutEverywhere:
    def test_change_password(self, service, ronaldo, sessions):
        _, token = service.login_with_session("ronaldo", STRONG)
        service.change_password(ronaldo.user_id, STRONG, NEW)
        with pytest.raises(InvalidSessionError):
            sessions.authenticate(token)

    def test_reset_password(self, service, ronaldo, sessions):
        _, token = service.login_with_session("ronaldo", STRONG)
        service.reset_password(service.request_password_reset("ronaldo@example.com"), NEW)
        with pytest.raises(InvalidSessionError):
            sessions.authenticate(token)

    def test_login_with_session(self, service, ronaldo, sessions):
        user, token = service.login_with_session("ronaldo", STRONG)
        assert sessions.authenticate(token) == user

    def test_service_without_sessions(self, db, clock, fast_hasher):
        from auth import AuthService, SQLiteRoleRepository, SQLiteUserRepository

        bare = AuthService(SQLiteUserRepository(db), SQLiteRoleRepository(db),
                           SQLiteResetTokenRepository(db), db.transaction,
                           hasher=fast_hasher, clock=clock)
        bare.register("ronaldo", "ronaldo@example.com", STRONG)
        with pytest.raises(ValidationError):
            bare.login_with_session("ronaldo", STRONG)
        bare.change_password(1, STRONG, NEW)   # works without sessions too


def events(db) -> list[str]:
    return [e.event.value for e in reversed(SQLiteAuditLog(db).recent())]


class TestAuditLog:
    def test_sign_up_and_logins_are_recorded(self, service, ronaldo, db):
        service.login("ronaldo", STRONG)
        with pytest.raises(InvalidCredentialsError):
            service.login("ronaldo", "wrong")
        with pytest.raises(InvalidCredentialsError):
            service.login("ghost", "wrong")
        assert events(db) == ["registered", "login_ok", "login_failed", "login_failed"]

    def test_unknown_names_are_not_written_down(self, service, db):
        with pytest.raises(InvalidCredentialsError):
            service.login("My-Password-Typed-Here", "x")
        entry = SQLiteAuditLog(db).recent()[0]
        assert entry.username is None
        assert "My-Password" not in entry.details

    def test_passwords_and_tokens_never_appear(self, service, ronaldo, db):
        token = service.request_password_reset("ronaldo@example.com")
        service.reset_password(token, NEW)
        everything = " ".join(str(e) for e in SQLiteAuditLog(db).recent())
        for secret in (STRONG, NEW, token):
            assert secret not in everything

    def test_lockout_is_recorded(self, service, ronaldo, db):
        for _ in range(5):
            with pytest.raises(Exception):
                service.login("ronaldo", "wrong")
        with pytest.raises(Exception):
            service.login("ronaldo", STRONG)
        assert events(db)[-2:] == ["account_locked", "login_refused"]

    def test_logout_is_recorded(self, service, ronaldo, sessions, db):
        _, token = service.login_with_session("ronaldo", STRONG)
        sessions.end(token)
        assert events(db)[-1] == "logged_out"

    def test_admin_actions_are_recorded_with_who_did_them(self, team, admin, db):
        ronaldo = team.get_user(1)
        admin.grant_role(ronaldo, 2, "moderator")
        admin.deactivate(ronaldo, 3)
        admin.activate(ronaldo, 3)
        admin.unlock(ronaldo, 3)
        admin.revoke_role(ronaldo, 2, "moderator")
        latest = SQLiteAuditLog(db).recent(limit=5)
        assert [e.event for e in reversed(latest)] == [
            AuditEvent.ROLE_GRANTED, AuditEvent.ACCOUNT_DEACTIVATED, AuditEvent.ACCOUNT_ACTIVATED,
            AuditEvent.ACCOUNT_UNLOCKED, AuditEvent.ROLE_REVOKED]
        assert latest[0].details == "moderator by ronaldo"

    def test_admin_reads_the_log_and_users_cannot(self, team, admin):
        entries = admin.audit_log(team.get_user(1), user_id=2)
        assert [e.username for e in entries] == ["amara"]
        assert admin.audit_log(team.get_user(1), event=AuditEvent.REGISTERED, limit=2)[0].username \
            == "tendai"
        with pytest.raises(PermissionDeniedError):
            admin.audit_log(team.get_user(2))

    def test_entry_text(self, service, ronaldo, db, clock):
        entry = SQLiteAuditLog(db).recent()[0]
        assert str(entry) == "2026-10-15 09:00:00  registered            ronaldo  first account, made admin"

    def test_null_log_records_nothing(self):
        log = NullAuditLog()
        log.record(AuditEvent.LOGIN_OK)
        assert log.recent() == []
