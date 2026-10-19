"""Tests for roles, permissions and the admin actions."""

from __future__ import annotations

import pytest

from auth import (
    ADMIN,
    MODERATOR,
    LockoutPolicy,
    USER,
    AccessControl,
    AdminService,
    Permission,
    PermissionDeniedError,
    Role,
    RoleRegistry,
    SQLiteRoleRepository,
    SQLiteUserRepository,
    ValidationError,
    requires,
)

RONALDO, AMARA, TENDAI = 1, 2, 3


@pytest.fixture
def access(db) -> AccessControl:
    return AccessControl(SQLiteRoleRepository(db))


def user(service, user_id):
    return service.get_user(user_id)


class TestRoles:
    def test_admin_can_do_everything(self):
        assert all(ADMIN.allows(p) for p in Permission)

    def test_user_can_only_look_after_themselves(self):
        assert USER.permissions == {Permission.VIEW_OWN_PROFILE, Permission.CHANGE_OWN_PASSWORD}

    def test_moderator_sits_in_between(self):
        assert USER.permissions < MODERATOR.permissions < ADMIN.permissions
        assert not MODERATOR.allows(Permission.MANAGE_ROLES)

    def test_registry(self):
        registry = RoleRegistry()
        assert registry.names == ("user", "moderator", "admin")
        with pytest.raises(ValidationError, match="Unknown role"):
            registry.get("king")
        with pytest.raises(ValidationError):
            registry.add(USER)

    def test_a_new_role_can_be_added(self, team, db):
        auditor = Role("auditor", frozenset({Permission.VIEW_AUDIT_LOG}))
        access = AccessControl(SQLiteRoleRepository(db), RoleRegistry([USER, MODERATOR, ADMIN, auditor]))
        SQLiteRoleRepository(db).grant(AMARA, "auditor", team.now)
        assert access.can(user(team, AMARA), Permission.VIEW_AUDIT_LOG)
        assert not access.can(user(team, AMARA), Permission.VIEW_USERS)


class TestSignUpRoles:
    def test_first_account_is_admin_the_rest_are_users(self, team, access):
        assert [r.name for r in access.roles_of(user(team, RONALDO))] == ["admin", "user"]
        assert [r.name for r in access.roles_of(user(team, AMARA))] == ["user"]


class TestAccessControl:
    def test_can_and_require(self, team, access):
        amara = user(team, AMARA)
        assert access.can(amara, Permission.CHANGE_OWN_PASSWORD)
        assert not access.can(amara, Permission.VIEW_USERS)
        with pytest.raises(PermissionDeniedError, match="amara isn't allowed to view users"):
            access.require(amara, Permission.VIEW_USERS)

    def test_roles_add_up(self, team, access, db):
        SQLiteRoleRepository(db).grant(AMARA, "moderator", team.now)
        assert access.permissions_of(user(team, AMARA)) == MODERATOR.permissions

    def test_switched_off_account_has_no_permissions(self, team, access, db):
        ronaldo = user(team, RONALDO)
        ronaldo.deactivate()
        assert access.permissions_of(ronaldo) == frozenset()

    def test_unknown_role_in_the_database_is_ignored(self, team, access, db):
        SQLiteRoleRepository(db).grant(AMARA, "superuser", team.now)
        assert access.permissions_of(user(team, AMARA)) == USER.permissions

    def test_unsaved_user_has_no_roles(self, access):
        from datetime import datetime

        from auth import User

        assert access.roles_of(User("ghost", "g@example.com", "x", datetime(2026, 1, 1))) == []


class TestRequiresDecorator:
    def test_checks_before_running(self, team, access):
        ran = []

        class Thing:
            _access = access

            @requires(Permission.VIEW_USERS)
            def secret(self, actor):
                ran.append(actor.username)
                return "ok"

        assert Thing().secret(user(team, RONALDO)) == "ok"
        with pytest.raises(PermissionDeniedError):
            Thing().secret(user(team, AMARA))
        assert ran == ["ronaldo"]
        assert Thing.secret.required_permission is Permission.VIEW_USERS
        assert Thing.secret.__name__ == "secret"


class TestAdminService:
    def test_list_users_with_roles(self, team, admin):
        rows = admin.list_users(user(team, RONALDO))
        assert [(u.username, roles) for u, roles in rows] == [
            ("ronaldo", ["admin", "user"]), ("amara", ["user"]), ("tendai", ["user"])]

    def test_plain_users_are_refused_everything(self, team, admin):
        amara = user(team, AMARA)
        for action in (lambda: admin.list_users(amara),
                       lambda: admin.deactivate(amara, TENDAI),
                       lambda: admin.unlock(amara, TENDAI),
                       lambda: admin.grant_role(amara, AMARA, "admin")):
            with pytest.raises(PermissionDeniedError):
                action()

    def test_grant_and_revoke(self, team, admin, access):
        ronaldo = user(team, RONALDO)
        assert admin.grant_role(ronaldo, AMARA, "moderator")
        assert not admin.grant_role(ronaldo, AMARA, "moderator")
        assert access.can(user(team, AMARA), Permission.LOCK_USERS)
        assert admin.revoke_role(ronaldo, AMARA, "moderator")
        assert not admin.revoke_role(ronaldo, AMARA, "moderator")

    def test_unknown_role_or_user(self, team, admin):
        from auth import UserNotFoundError

        with pytest.raises(ValidationError):
            admin.grant_role(user(team, RONALDO), AMARA, "king")
        with pytest.raises(UserNotFoundError):
            admin.grant_role(user(team, RONALDO), 99, "moderator")

    def test_last_admin_cannot_be_removed(self, team, admin):
        ronaldo = user(team, RONALDO)
        with pytest.raises(ValidationError, match="last admin"):
            admin.revoke_role(ronaldo, RONALDO, "admin")
        admin.grant_role(ronaldo, AMARA, "admin")
        assert admin.revoke_role(ronaldo, RONALDO, "admin")

    def test_moderator_can_switch_users_off_and_on(self, team, admin):
        admin.grant_role(user(team, RONALDO), AMARA, "moderator")
        amara = user(team, AMARA)
        assert not admin.deactivate(amara, TENDAI).is_active
        assert admin.activate(amara, TENDAI).is_active

    def test_moderator_cannot_switch_off_an_admin(self, team, admin):
        admin.grant_role(user(team, RONALDO), AMARA, "moderator")
        with pytest.raises(PermissionDeniedError, match="another admin"):
            admin.deactivate(user(team, AMARA), RONALDO)

    def test_admin_can_switch_off_another_admin(self, team, admin):
        ronaldo = user(team, RONALDO)
        admin.grant_role(ronaldo, AMARA, "admin")
        assert not admin.deactivate(ronaldo, AMARA).is_active

    def test_cannot_switch_yourself_off(self, team, admin):
        with pytest.raises(ValidationError, match="your own"):
            admin.deactivate(user(team, RONALDO), RONALDO)

    def test_unlock(self, team, admin, db):
        from datetime import timedelta

        tendai = user(team, TENDAI)
        tendai.record_failed_login(team.now, LockoutPolicy(max_attempts=1))
        SQLiteUserRepository(db).update(tendai)
        assert user(team, TENDAI).is_locked(team.now)
        admin.unlock(user(team, RONALDO), TENDAI)
        assert not user(team, TENDAI).is_locked(team.now + timedelta(seconds=1))


def test_role_repository_unknown_user(db, clock):
    with pytest.raises(ValidationError):
        SQLiteRoleRepository(db).grant(99, "user", clock.now)


def test_default_setup_works(db, service):
    service.register("ronaldo", "ronaldo@example.com", "Purple-Hibiscus-2003")
    admin = AdminService.open(db)
    assert admin.grant_role(service.get_user(1), 1, "moderator")
