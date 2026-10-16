"""The SQLite database: opening it, setting up the tables, and transactions.

The same pattern as the Week 3 library: numbered migrations, foreign keys
switched on, and every value passed as a ? parameter.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from .exceptions import DatabaseError

IN_MEMORY = ":memory:"

# Each entry upgrades the database by one version. Never edit an old entry,
# because databases already out there have run it. Add a new one instead.
MIGRATIONS: tuple[tuple[str, ...], ...] = (
    # Version 1: users. COLLATE NOCASE makes "Ronaldo" and "ronaldo" the same username.
    (
        """
        CREATE TABLE users (
            user_id        INTEGER PRIMARY KEY,
            username       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            email          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash  TEXT    NOT NULL,
            created_at     TEXT    NOT NULL,
            is_active      INTEGER NOT NULL DEFAULT 1,
            failed_logins  INTEGER NOT NULL DEFAULT 0,
            locked_until   TEXT,
            last_login_at  TEXT
        )
        """,
    ),
)


class Database:
    """One open SQLite database.

    Use it in a with block so it always gets closed:

        with Database("data/auth.db") as db:
            ...
    """

    def __init__(self, path: str | Path = IN_MEMORY) -> None:
        self._path = str(path)
        if self._path != IN_MEMORY:
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        try:
            # isolation_level=None means we start and finish transactions
            # ourselves, in transaction() below.
            self._connection = sqlite3.connect(self._path, isolation_level=None)
        except sqlite3.Error as error:
            raise DatabaseError(f"Could not open {self._path}: {error}") from error
        self._connection.row_factory = sqlite3.Row
        self._depth = 0
        try:
            # SQLite leaves foreign key checks off unless asked.
            self.execute("PRAGMA foreign_keys = ON")
            self._migrate()
        except Exception:
            self._connection.close()
            raise

    @property
    def path(self) -> str:
        return self._path

    @property
    def schema_version(self) -> int:
        return self.execute("PRAGMA user_version").fetchone()[0]

    # ------------------------------------------------------------------
    # Running SQL
    # ------------------------------------------------------------------

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        """Run one statement. Always pass values as params, never paste them
        into the SQL text, so a username like "x'; DROP TABLE users" is just
        text.

        sqlite3.IntegrityError is passed on as it is, so the caller can say
        what was duplicated. Any other database problem becomes a DatabaseError.
        """
        try:
            return self._connection.execute(sql, params)
        except sqlite3.IntegrityError:
            raise
        except sqlite3.Error as error:
            raise DatabaseError(f"Database problem: {error}") from error

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Everything inside happens together, or none of it does.

        Like paying at a till: the money and the shopping change hands
        together, or the sale is cancelled. Using it inside another
        transaction just joins the outer one.
        """
        if self._depth:
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
            return

        self.execute("BEGIN")
        self._depth = 1
        try:
            yield
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        else:
            self.execute("COMMIT")
        finally:
            self._depth = 0

    # ------------------------------------------------------------------
    # Setting up and closing
    # ------------------------------------------------------------------

    def _migrate(self) -> None:
        """Bring the tables up to date, one version at a time."""
        current = self.schema_version
        if current > len(MIGRATIONS):
            raise DatabaseError(
                f"{self._path} was made by a newer version of this program "
                f"(database version {current}, this program knows up to {len(MIGRATIONS)})."
            )
        for version in range(current + 1, len(MIGRATIONS) + 1):
            with self.transaction():
                for statement in MIGRATIONS[version - 1]:
                    self.execute(statement)
                # PRAGMA can't take a ? placeholder. version is our own int, so this is safe.
                self.execute(f"PRAGMA user_version = {version}")

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"Database({self._path!r})"
