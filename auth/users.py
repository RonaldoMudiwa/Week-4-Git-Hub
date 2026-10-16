"""Saving and finding users."""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime

from .database import Database
from .exceptions import DuplicateError, UserNotFoundError, ValidationError
from .user import User


class UserRepository(ABC):
    @abstractmethod
    def add(self, user: User) -> User:
        """Save a new user. Their user_id is filled in."""

    @abstractmethod
    def get(self, user_id: int) -> User:
        """Raises UserNotFoundError if there's no such user."""

    @abstractmethod
    def find_by_username(self, username: str) -> User | None:
        """Case doesn't matter. None if nobody has it."""

    @abstractmethod
    def find_by_email(self, email: str) -> User | None:
        """Case doesn't matter. None if nobody has it."""

    @abstractmethod
    def update(self, user: User) -> None:
        """Save every change to a user."""

    @abstractmethod
    def all(self) -> list[User]:
        """Every user, oldest account first."""

    def find_for_login(self, name_or_email: str) -> User | None:
        """People log in with either, so look in both places."""
        text = str(name_or_email).strip()
        if "@" in text:
            return self.find_by_email(text)
        return self.find_by_username(text)


class SQLiteUserRepository(UserRepository):
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, user: User) -> User:
        if user.user_id is not None:
            raise ValidationError("This user has already been saved.")
        try:
            cursor = self._db.execute(
                "INSERT INTO users (username, email, password_hash, created_at, is_active, "
                "failed_logins, locked_until, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user.username, user.email, user.password_hash, user.created_at.isoformat(),
                 int(user.is_active), user.failed_logins, _iso(user.locked_until),
                 _iso(user.last_login_at)),
            )
        except sqlite3.IntegrityError as error:
            raise DuplicateError(self._which_is_taken(user, error)) from None
        user.assign_id(cursor.lastrowid)
        return user

    def get(self, user_id: int) -> User:
        row = self._db.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
        if row is None:
            raise UserNotFoundError(f"No user with id {user_id}.")
        return self._to_user(row)

    def find_by_username(self, username: str) -> User | None:
        row = self._db.query_one("SELECT * FROM users WHERE username = ?",
                                 (str(username).strip(),))
        return self._to_user(row) if row else None

    def find_by_email(self, email: str) -> User | None:
        row = self._db.query_one("SELECT * FROM users WHERE email = ?", (str(email).strip(),))
        return self._to_user(row) if row else None

    def update(self, user: User) -> None:
        if user.user_id is None:
            raise ValidationError("Save the user with add() before updating them.")
        try:
            cursor = self._db.execute(
                "UPDATE users SET email = ?, password_hash = ?, is_active = ?, failed_logins = ?, "
                "locked_until = ?, last_login_at = ? WHERE user_id = ?",
                (user.email, user.password_hash, int(user.is_active), user.failed_logins,
                 _iso(user.locked_until), _iso(user.last_login_at), user.user_id),
            )
        except sqlite3.IntegrityError as error:
            raise DuplicateError(self._which_is_taken(user, error)) from None
        if cursor.rowcount == 0:
            raise UserNotFoundError(f"No user with id {user.user_id}.")

    def all(self) -> list[User]:
        return [self._to_user(row) for row in self._db.query("SELECT * FROM users ORDER BY user_id")]

    @staticmethod
    def _which_is_taken(user: User, error: sqlite3.IntegrityError) -> str:
        # SQLite names the column that clashed, e.g. "users.email".
        if "email" in str(error):
            return f"The email {user.email} is already registered."
        return f"The username {user.username} is already taken."

    @staticmethod
    def _to_user(row: sqlite3.Row) -> User:
        return User(
            row["username"], row["email"], row["password_hash"],
            datetime.fromisoformat(row["created_at"]),
            is_active=bool(row["is_active"]),
            failed_logins=row["failed_logins"],
            locked_until=_from_iso(row["locked_until"]),
            last_login_at=_from_iso(row["last_login_at"]),
            user_id=row["user_id"],
        )


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _from_iso(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None
