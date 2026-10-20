"""The audit log: a diary of everything security related that happened.

If an account is broken into, this is where you look to see when, and what
was done. Entries are only ever added, never changed. Passwords and tokens
are never written here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, unique
from typing import Callable

from .database import Database
from .user import User


@unique
class AuditEvent(Enum):
    REGISTERED = "registered"
    LOGIN_OK = "login_ok"
    LOGIN_FAILED = "login_failed"
    ACCOUNT_LOCKED = "account_locked"
    LOGIN_REFUSED = "login_refused"          # right password, but switched off or locked
    LOGGED_OUT = "logged_out"
    LOGGED_OUT_EVERYWHERE = "logged_out_everywhere"
    PASSWORD_CHANGED = "password_changed"
    RESET_REQUESTED = "reset_requested"
    PASSWORD_RESET = "password_reset"
    ROLE_GRANTED = "role_granted"
    ROLE_REVOKED = "role_revoked"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    ACCOUNT_ACTIVATED = "account_activated"
    ACCOUNT_UNLOCKED = "account_unlocked"


@dataclass(frozen=True)
class AuditEntry:
    happened_at: datetime
    event: AuditEvent
    user_id: int | None
    username: str | None
    details: str = ""
    event_id: int | None = None

    def __str__(self) -> str:
        who = self.username or "-"
        extra = f"  {self.details}" if self.details else ""
        return f"{self.happened_at:%Y-%m-%d %H:%M:%S}  {self.event.value:<22}{who}{extra}"


class AuditLog(ABC):
    @abstractmethod
    def record(self, event: AuditEvent, user: User | None = None, details: str = "") -> None:
        """Add an entry. Never put a password or token in details."""

    @abstractmethod
    def recent(self, limit: int = 50, user_id: int | None = None,
               event: AuditEvent | None = None) -> list[AuditEntry]:
        """Newest first. Filter by user or event if given."""


class NullAuditLog(AuditLog):
    """Writes nothing. Used when no log is wanted, so the code that records
    events never has to check "is there a log?" first."""

    def record(self, event: AuditEvent, user: User | None = None, details: str = "") -> None:
        pass

    def recent(self, limit: int = 50, user_id: int | None = None,
               event: AuditEvent | None = None) -> list[AuditEntry]:
        return []


class SQLiteAuditLog(AuditLog):
    def __init__(self, db: Database, clock: Callable[[], datetime] | None = None) -> None:
        self._db = db
        self._clock = clock or datetime.now

    def record(self, event: AuditEvent, user: User | None = None, details: str = "") -> None:
        self._db.execute(
            "INSERT INTO audit_log (happened_at, event, user_id, username, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (self._clock().isoformat(), event.value, user.user_id if user else None,
             user.username if user else None, details),
        )

    def recent(self, limit: int = 50, user_id: int | None = None,
               event: AuditEvent | None = None) -> list[AuditEntry]:
        conditions, params = [], []
        if user_id is not None:
            conditions.append("user_id = ?")
            params.append(user_id)
        if event is not None:
            conditions.append("event = ?")
            params.append(event.value)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        rows = self._db.query(f"SELECT * FROM audit_log{where} "
                              "ORDER BY happened_at DESC, event_id DESC LIMIT ?", (*params, limit))
        return [AuditEntry(datetime.fromisoformat(r["happened_at"]), AuditEvent(r["event"]),
                           r["user_id"], r["username"], r["details"], r["event_id"])
                for r in rows]
