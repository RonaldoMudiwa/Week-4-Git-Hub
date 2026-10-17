"""A user account."""

from __future__ import annotations

from datetime import datetime

from .exceptions import ValidationError
from .lockout import LockoutPolicy
from .validation import clean_email, clean_username


class User:
    """Someone who can log in.

    The password itself is never kept here, only its hash. The hash can only
    be replaced through set_password_hash(), never edited by accident.
    """

    def __init__(
        self,
        username: str,
        email: str,
        password_hash: str,
        created_at: datetime,
        *,
        is_active: bool = True,
        failed_logins: int = 0,
        locked_until: datetime | None = None,
        last_login_at: datetime | None = None,
        user_id: int | None = None,
    ) -> None:
        self._username = clean_username(username)
        self.email = email
        self.set_password_hash(password_hash)
        if not isinstance(created_at, datetime):
            raise ValidationError("created_at must be a datetime.")
        self._created_at = created_at
        self._is_active = bool(is_active)
        if isinstance(failed_logins, bool) or not isinstance(failed_logins, int) or failed_logins < 0:
            raise ValidationError("failed_logins must be a whole number, 0 or more.")
        self._failed_logins = failed_logins
        self._locked_until = locked_until
        self._last_login_at = last_login_at
        self._user_id: int | None = None
        if user_id is not None:
            self.assign_id(user_id)

    # ------------------------------------------------------------------
    # Details
    # ------------------------------------------------------------------

    @property
    def user_id(self) -> int | None:
        return self._user_id

    def assign_id(self, user_id: int) -> None:
        """Set by the database when the user is first saved. Only once."""
        if self._user_id is not None:
            raise ValidationError("This user already has an id.")
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            raise ValidationError("User id must be a whole number above zero.")
        self._user_id = user_id

    @property
    def username(self) -> str:
        """Can't be changed, because other records point to it."""
        return self._username

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        self._email = clean_email(value)

    @property
    def password_hash(self) -> str:
        return self._password_hash

    def set_password_hash(self, password_hash: str) -> None:
        if not isinstance(password_hash, str) or not password_hash:
            raise ValidationError("A password hash is required.")
        self._password_hash = password_hash

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def last_login_at(self) -> datetime | None:
        return self._last_login_at

    # ------------------------------------------------------------------
    # Account state
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        """False once an admin switches the account off."""
        return self._is_active

    def deactivate(self) -> None:
        self._is_active = False

    def activate(self) -> None:
        self._is_active = True

    @property
    def failed_logins(self) -> int:
        """Wrong passwords in a row since the last good log in."""
        return self._failed_logins

    @property
    def locked_until(self) -> datetime | None:
        return self._locked_until

    def is_locked(self, now: datetime) -> bool:
        return self._locked_until is not None and now < self._locked_until

    def record_failed_login(self, now: datetime, policy: LockoutPolicy) -> bool:
        """Count a wrong password. Returns True if this one locked the account."""
        self._failed_logins += 1
        if self._failed_logins >= policy.max_attempts:
            self._locked_until = now + policy.lock_for
            # Start counting again once the lock runs out.
            self._failed_logins = 0
            return True
        return False

    def record_successful_login(self, now: datetime) -> None:
        self._failed_logins = 0
        self._locked_until = None
        self._last_login_at = now

    def unlock(self) -> None:
        """Lift a lock early, e.g. an admin after checking it's really them."""
        self._failed_logins = 0
        self._locked_until = None

    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, User):
            return NotImplemented
        return self._username == other._username

    def __hash__(self) -> int:
        return hash(self._username)

    def __repr__(self) -> str:
        # The hash is left out on purpose, so it never ends up in a log.
        return f"User({self._username!r}, {self._email!r}, user_id={self._user_id})"

    def __str__(self) -> str:
        return self._username
