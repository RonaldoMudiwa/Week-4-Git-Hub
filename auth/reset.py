"""Password reset links, for people who forgot their password.

A reset link holds a one-time random token. Like the sessions, only a hash
of it is saved. It works once, for one hour.
"""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from .database import Database
from .exceptions import ValidationError

RESET_LIFETIME = timedelta(hours=1)


@dataclass(frozen=True)
class ResetToken:
    user_id: int
    token_hash: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    reset_id: int | None = None

    def is_usable(self, now: datetime) -> bool:
        return self.used_at is None and now < self.expires_at

    def with_changes(self, **changes) -> "ResetToken":
        return replace(self, **changes)


class ResetTokenRepository(ABC):
    @abstractmethod
    def add(self, token: ResetToken) -> ResetToken:
        """Save a new reset token."""

    @abstractmethod
    def find(self, token_hash: str) -> ResetToken | None:
        """The token with this hash, or None."""

    @abstractmethod
    def mark_used(self, reset_id: int, when: datetime) -> None:
        """Stop a token working again."""

    @abstractmethod
    def cancel_unused(self, user_id: int, when: datetime) -> None:
        """Mark every unused token for this user as used. Only the newest link should work."""


class SQLiteResetTokenRepository(ResetTokenRepository):
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, token: ResetToken) -> ResetToken:
        try:
            cursor = self._db.execute(
                "INSERT INTO reset_tokens (token_hash, user_id, created_at, expires_at, used_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (token.token_hash, token.user_id, token.created_at.isoformat(),
                 token.expires_at.isoformat(), token.used_at.isoformat() if token.used_at else None),
            )
        except sqlite3.IntegrityError:
            raise ValidationError("That user doesn't exist, or the token is already used.") from None
        return token.with_changes(reset_id=cursor.lastrowid)

    def find(self, token_hash: str) -> ResetToken | None:
        row = self._db.query_one("SELECT * FROM reset_tokens WHERE token_hash = ?", (token_hash,))
        if row is None:
            return None
        return ResetToken(row["user_id"], row["token_hash"],
                          datetime.fromisoformat(row["created_at"]),
                          datetime.fromisoformat(row["expires_at"]),
                          datetime.fromisoformat(row["used_at"]) if row["used_at"] else None,
                          row["reset_id"])

    def mark_used(self, reset_id: int, when: datetime) -> None:
        self._db.execute("UPDATE reset_tokens SET used_at = ? WHERE reset_id = ?",
                         (when.isoformat(), reset_id))

    def cancel_unused(self, user_id: int, when: datetime) -> None:
        self._db.execute("UPDATE reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                         (when.isoformat(), user_id))
