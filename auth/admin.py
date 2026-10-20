"""Things only some users are allowed to do, like switching accounts off.

Every method takes actor, the logged in user doing it, and @requires checks
their permission before anything happens.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, ContextManager

from .audit import AuditEntry, AuditEvent, AuditLog, NullAuditLog, SQLiteAuditLog
from .database import Database
from .exceptions import PermissionDeniedError, ValidationError
from .permissions import ADMIN, AccessControl, Permission, RoleRepository, SQLiteRoleRepository, requires
from .user import User
from .users import SQLiteUserRepository, UserRepository


class AdminService:
    def __init__(
        self,
        users: UserRepository,
        roles: RoleRepository,
        access: AccessControl,
        transaction: Callable[[], ContextManager[None]],
        clock: Callable[[], datetime] | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._users = users
        self._roles = roles
        self._access = access
        self._transaction = transaction
        self._clock = clock or datetime.now
        self._audit = audit or NullAuditLog()

    @classmethod
    def open(cls, db: Database, clock: Callable[[], datetime] | None = None) -> "AdminService":
        roles = SQLiteRoleRepository(db)
        return cls(SQLiteUserRepository(db), roles, AccessControl(roles), db.transaction, clock,
                   SQLiteAuditLog(db, clock))

    @property
    def access(self) -> AccessControl:
        return self._access

    @requires(Permission.VIEW_USERS)
    def list_users(self, actor: User) -> list[tuple[User, list[str]]]:
        """Every user with the names of their roles."""
        return [(user, sorted(self._roles.roles_for(user.user_id))) for user in self._users.all()]

    @requires(Permission.LOCK_USERS)
    def deactivate(self, actor: User, user_id: int) -> User:
        if user_id == actor.user_id:
            raise ValidationError("You can't switch off your own account.")
        user = self._users.get(user_id)
        if ADMIN.name in self._roles.roles_for(user_id) and not self._access.can(
                actor, Permission.MANAGE_ROLES):
            raise PermissionDeniedError("Only an admin can switch off another admin.")
        user.deactivate()
        self._users.update(user)
        self._audit.record(AuditEvent.ACCOUNT_DEACTIVATED, user, f"by {actor.username}")
        return user

    @requires(Permission.LOCK_USERS)
    def activate(self, actor: User, user_id: int) -> User:
        user = self._users.get(user_id)
        user.activate()
        self._users.update(user)
        self._audit.record(AuditEvent.ACCOUNT_ACTIVATED, user, f"by {actor.username}")
        return user

    @requires(Permission.LOCK_USERS)
    def unlock(self, actor: User, user_id: int) -> User:
        user = self._users.get(user_id)
        user.unlock()
        self._users.update(user)
        self._audit.record(AuditEvent.ACCOUNT_UNLOCKED, user, f"by {actor.username}")
        return user

    @requires(Permission.MANAGE_ROLES)
    def grant_role(self, actor: User, user_id: int, role: str) -> bool:
        """Returns False if they already had it."""
        name = self._access.registry.get(role).name
        user = self._users.get(user_id)
        granted = self._roles.grant(user_id, name, self._clock())
        if granted:
            self._audit.record(AuditEvent.ROLE_GRANTED, user, f"{name} by {actor.username}")
        return granted

    @requires(Permission.MANAGE_ROLES)
    def revoke_role(self, actor: User, user_id: int, role: str) -> bool:
        """Returns False if they didn't have it. The last admin can't be removed,
        or nobody could ever manage roles again."""
        name = self._access.registry.get(role).name
        with self._transaction():
            if name == ADMIN.name and self._roles.users_with(ADMIN.name) == [user_id]:
                raise ValidationError("That's the last admin. Make someone else admin first.")
            revoked = self._roles.revoke(user_id, name)
            if revoked:
                self._audit.record(AuditEvent.ROLE_REVOKED, self._users.get(user_id),
                                   f"{name} by {actor.username}")
            return revoked

    @requires(Permission.VIEW_AUDIT_LOG)
    def audit_log(self, actor: User, limit: int = 50, user_id: int | None = None,
                  event: AuditEvent | None = None) -> list[AuditEntry]:
        return self._audit.recent(limit, user_id, event)
