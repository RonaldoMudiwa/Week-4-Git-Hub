"""Login sessions: staying logged in without typing the password every time.

After a good log in, the user gets a long random token, like a wristband at
a festival. They show the token with each request instead of the password.

Only a hash of each token is saved. If someone stole the database, they'd
get hashes they can't use to log in as anyone.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Callable, ContextManager

from .database import Database
from .exceptions import (
    InvalidSessionError,
    SessionExpiredError,
    ValidationError,
)
from .user import User
from .users import UserRepository

TOKEN_BYTES = 32  # 256 random bits, far too many to guess


def hash_token(token: str) -> str:
    """SHA-256 of the token.

    A fast hash is fine here, unlike for passwords. Tokens are completely
    random, so there's no list of likely tokens to try.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SessionPolicy:
    """How long a session lasts.

    idle_timeout: logged out after this long with no activity.
    max_age: logged out after this long no matter what.
    """

    idle_timeout: timedelta = timedelta(minutes=30)
    max_age: timedelta = timedelta(hours=12)

    def __post_init__(self) -> None:
        for name in ("idle_timeout", "max_age"):
            value = getattr(self, name)
            if not isinstance(value, timedelta) or value <= timedelta(0):
                raise ValidationError(f"{name} must be a length of time above zero.")


@dataclass(frozen=True)
class Session:
    user_id: int
    token_hash: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ended_at: datetime | None = None
    session_id: int | None = None

    def is_live(self, now: datetime, idle_timeout: timedelta) -> bool:
        return (self.ended_at is None and now < self.expires_at
                and now - self.last_seen_at < idle_timeout)

    def with_changes(self, **changes) -> "Session":
        return replace(self, **changes)


class SessionRepository(ABC):
    @abstractmethod
    def add(self, session: Session) -> Session:
        """Save a new session and return it with its session_id."""

    @abstractmethod
    def find(self, token_hash: str) -> Session | None:
        """The session with this token hash, or None."""

    @abstractmethod
    def update(self, session: Session) -> None:
        """Save last_seen_at or ended_at."""

    @abstractmethod
    def open_for_user(self, user_id: int) -> list[Session]:
        """Sessions not yet logged out, newest first. Some may have timed out."""

    @abstractmethod
    def delete_older_than(self, moment: datetime) -> int:
        """Remove sessions that ended or expired before this moment. Returns how many."""


class SQLiteSessionRepository(SessionRepository):
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, session: Session) -> Session:
        try:
            cursor = self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, "
                "ended_at) VALUES (?, ?, ?, ?, ?, ?)",
                (session.token_hash, session.user_id, session.created_at.isoformat(),
                 session.last_seen_at.isoformat(), session.expires_at.isoformat(),
                 _iso(session.ended_at)),
            )
        except sqlite3.IntegrityError:
            raise ValidationError("That user doesn't exist, or the token is already used.") from None
        return session.with_changes(session_id=cursor.lastrowid)

    def find(self, token_hash: str) -> Session | None:
        row = self._db.query_one("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,))
        return self._to_session(row) if row else None

    def update(self, session: Session) -> None:
        self._db.execute("UPDATE sessions SET last_seen_at = ?, ended_at = ? WHERE session_id = ?",
                         (session.last_seen_at.isoformat(), _iso(session.ended_at),
                          session.session_id))

    def open_for_user(self, user_id: int) -> list[Session]:
        rows = self._db.query("SELECT * FROM sessions WHERE user_id = ? AND ended_at IS NULL "
                              "ORDER BY created_at DESC, session_id DESC", (user_id,))
        return [self._to_session(row) for row in rows]

    def delete_older_than(self, moment: datetime) -> int:
        cursor = self._db.execute(
            "DELETE FROM sessions WHERE ended_at < ? OR expires_at < ?",
            (moment.isoformat(), moment.isoformat()),
        )
        return cursor.rowcount

    @staticmethod
    def _to_session(row: sqlite3.Row) -> Session:
        return Session(row["user_id"], row["token_hash"],
                       datetime.fromisoformat(row["created_at"]),
                       datetime.fromisoformat(row["last_seen_at"]),
                       datetime.fromisoformat(row["expires_at"]),
                       datetime.fromisoformat(row["ended_at"]) if row["ended_at"] else None,
                       row["session_id"])


class SessionManager:
    """Hands out session tokens, checks them, and ends them."""

    def __init__(
        self,
        sessions: SessionRepository,
        users: UserRepository,
        transaction: Callable[[], ContextManager[None]],
        policy: SessionPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sessions = sessions
        self._users = users
        self._transaction = transaction
        self._policy = policy or SessionPolicy()
        self._clock = clock or datetime.now

    @classmethod
    def open(cls, db: Database, **options) -> "SessionManager":
        from .users import SQLiteUserRepository

        return cls(SQLiteSessionRepository(db), SQLiteUserRepository(db), db.transaction, **options)

    def start(self, user: User) -> str:
        """Start a session for someone who just logged in. Returns the token.

        This is the only time the token itself exists. Give it to the user
        and don't keep a copy.
        """
        if user.user_id is None:
            raise ValidationError("Only a saved user can have a session.")
        now = self._clock()
        token = secrets.token_urlsafe(TOKEN_BYTES)
        self._sessions.add(Session(user.user_id, hash_token(token), now, now,
                                   now + self._policy.max_age))
        return token

    def authenticate(self, token: str) -> User:
        """Who does this token belong to? Also counts as activity, so the
        idle timer starts again.

        Raises:
            InvalidSessionError: Unknown or logged out token, or the account
                was switched off.
            SessionExpiredError: The session timed out.
        """
        session = self._find(token)
        now = self._clock()
        if session.ended_at is not None:
            raise InvalidSessionError("You've been logged out. Please log in again.")
        if not session.is_live(now, self._policy.idle_timeout):
            raise SessionExpiredError("Your session has timed out. Please log in again.")
        user = self._users.get(session.user_id)
        if not user.is_active:
            raise InvalidSessionError("This account has been switched off.")
        self._sessions.update(session.with_changes(last_seen_at=now))
        return user

    def end(self, token: str) -> None:
        """Log out of this one session. Doing it twice is harmless."""
        session = self._find(token)
        if session.ended_at is None:
            self._sessions.update(session.with_changes(ended_at=self._clock()))

    def end_all(self, user_id: int) -> int:
        """Log out everywhere, e.g. after a password change. Returns how many ended."""
        now = self._clock()
        with self._transaction():
            open_sessions = self._sessions.open_for_user(user_id)
            for session in open_sessions:
                self._sessions.update(session.with_changes(ended_at=now))
        return len(open_sessions)

    def active_sessions(self, user_id: int) -> list[Session]:
        """Where someone is logged in right now, newest first."""
        now = self._clock()
        return [s for s in self._sessions.open_for_user(user_id)
                if s.is_live(now, self._policy.idle_timeout)]

    def purge(self, older_than: timedelta = timedelta(days=30)) -> int:
        """Delete old finished sessions so the table doesn't grow forever."""
        return self._sessions.delete_older_than(self._clock() - older_than)

    def _find(self, token: str) -> Session:
        if not isinstance(token, str) or not token:
            raise InvalidSessionError("No session token was given.")
        session = self._sessions.find(hash_token(token))
        if session is None:
            raise InvalidSessionError("That session doesn't exist. Please log in.")
        return session


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None
