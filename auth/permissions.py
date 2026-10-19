"""Roles and permissions: who is allowed to do what.

A permission is one thing someone can do, like "see every user". A role is
a named bundle of permissions, like "moderator". Users are given roles, and
a user can do anything any of their roles allows.

It's like a school: every pupil can use the library, prefects can also hand
out detentions, and the head can do everything. Nobody checks names, only
badges.
"""

from __future__ import annotations

import functools
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, unique
from typing import Callable, Iterable, TypeVar

from .database import Database
from .exceptions import PermissionDeniedError, ValidationError
from .user import User


@unique
class Permission(Enum):
    VIEW_OWN_PROFILE = "view_own_profile"
    CHANGE_OWN_PASSWORD = "change_own_password"
    VIEW_USERS = "view_users"
    LOCK_USERS = "lock_users"          # switch accounts off and on, unlock them
    MANAGE_ROLES = "manage_roles"
    VIEW_AUDIT_LOG = "view_audit_log"


@dataclass(frozen=True)
class Role:
    name: str
    permissions: frozenset[Permission]
    description: str = ""

    def allows(self, permission: Permission) -> bool:
        return permission in self.permissions


_BASIC = frozenset({Permission.VIEW_OWN_PROFILE, Permission.CHANGE_OWN_PASSWORD})

USER = Role("user", _BASIC, "Every account. Can see and look after their own account.")
MODERATOR = Role("moderator", _BASIC | {Permission.VIEW_USERS, Permission.LOCK_USERS},
                 "Can see every account and switch accounts off.")
ADMIN = Role("admin", frozenset(Permission), "Can do everything, including giving out roles.")


class RoleRegistry:
    """The roles that exist. New roles can be added without changing any checks."""

    def __init__(self, roles: Iterable[Role] = (USER, MODERATOR, ADMIN)) -> None:
        self._roles: dict[str, Role] = {}
        for role in roles:
            self.add(role)

    def add(self, role: Role) -> None:
        if role.name in self._roles:
            raise ValidationError(f"There's already a role called {role.name!r}.")
        self._roles[role.name] = role

    def get(self, name: str) -> Role:
        try:
            return self._roles[name]
        except KeyError:
            allowed = ", ".join(self._roles)
            raise ValidationError(f"Unknown role {name!r}. Choose from: {allowed}.") from None

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._roles)


class RoleRepository(ABC):
    @abstractmethod
    def roles_for(self, user_id: int) -> set[str]:
        """The names of every role this user has."""

    @abstractmethod
    def grant(self, user_id: int, role: str, when: datetime) -> bool:
        """Give a role. Returns False if they already had it."""

    @abstractmethod
    def revoke(self, user_id: int, role: str) -> bool:
        """Take a role away. Returns False if they didn't have it."""

    @abstractmethod
    def users_with(self, role: str) -> list[int]:
        """The ids of everyone with this role."""


class SQLiteRoleRepository(RoleRepository):
    def __init__(self, db: Database) -> None:
        self._db = db

    def roles_for(self, user_id: int) -> set[str]:
        rows = self._db.query("SELECT role FROM user_roles WHERE user_id = ?", (user_id,))
        return {row["role"] for row in rows}

    def grant(self, user_id: int, role: str, when: datetime) -> bool:
        try:
            # OR IGNORE skips the insert if they already have the role.
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role, granted_at) VALUES (?, ?, ?)",
                (user_id, role, when.isoformat()),
            )
        except sqlite3.IntegrityError:
            raise ValidationError(f"No user with id {user_id}.") from None
        return cursor.rowcount == 1

    def revoke(self, user_id: int, role: str) -> bool:
        cursor = self._db.execute("DELETE FROM user_roles WHERE user_id = ? AND role = ?",
                                  (user_id, role))
        return cursor.rowcount == 1

    def users_with(self, role: str) -> list[int]:
        rows = self._db.query("SELECT user_id FROM user_roles WHERE role = ? ORDER BY user_id",
                              (role,))
        return [row["user_id"] for row in rows]


class AccessControl:
    """Answers "can this user do this?"."""

    def __init__(self, roles: RoleRepository, registry: RoleRegistry | None = None) -> None:
        self._roles = roles
        self._registry = registry or RoleRegistry()

    @property
    def registry(self) -> RoleRegistry:
        return self._registry

    def roles_of(self, user: User) -> list[Role]:
        names = self._roles.roles_for(user.user_id) if user.user_id else set()
        # Roles that were removed from the registry are ignored, not trusted.
        return [self._registry.get(n) for n in sorted(names) if n in self._registry.names]

    def permissions_of(self, user: User) -> frozenset[Permission]:
        if not user.is_active:
            return frozenset()
        found: set[Permission] = set()
        for role in self.roles_of(user):
            found |= role.permissions
        return frozenset(found)

    def can(self, user: User, permission: Permission) -> bool:
        return permission in self.permissions_of(user)

    def require(self, user: User, permission: Permission) -> None:
        if not self.can(user, permission):
            raise PermissionDeniedError(
                f"{user.username} isn't allowed to {permission.value.replace('_', ' ')}."
            )


_Method = TypeVar("_Method", bound=Callable)


def requires(permission: Permission) -> Callable[[_Method], _Method]:
    """Put above a method to check a permission before it runs.

        @requires(Permission.VIEW_USERS)
        def list_users(self, actor): ...

    The method's first argument after self must be the user doing it, and
    the class needs an _access attribute holding an AccessControl. The
    check can't be forgotten, because it happens before the method starts.
    """
    def decorate(method: _Method) -> _Method:
        @functools.wraps(method)
        def wrapper(self, actor: User, *args, **kwargs):
            self._access.require(actor, permission)
            return method(self, actor, *args, **kwargs)
        wrapper.required_permission = permission  # handy for tests and help text
        return wrapper  # type: ignore[return-value]
    return decorate
