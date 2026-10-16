"""Tests for opening the database, setting up tables and transactions.

tmp_path gives each test its own empty folder, so real data is never touched.
"""

from __future__ import annotations

import sqlite3

import pytest

from auth import Database, DatabaseError
from auth.database import MIGRATIONS


def test_new_database_is_fully_set_up(db):
    assert db.schema_version == len(MIGRATIONS)
    tables = {row["name"] for row in db.query("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "users" in tables


def test_foreign_keys_are_switched_on(db):
    assert db.query_one("PRAGMA foreign_keys")[0] == 1


def test_file_database_keeps_data_between_runs(tmp_path):
    path = tmp_path / "sub" / "auth.db"
    with Database(path) as db:
        db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")
    assert path.exists()
    with Database(path) as db:
        assert db.query_one("SELECT username FROM users")["username"] == "a"
        assert db.schema_version == len(MIGRATIONS)


def test_database_from_a_newer_program_is_refused(tmp_path):
    path = tmp_path / "auth.db"
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA user_version = {len(MIGRATIONS) + 1}")
    connection.close()
    with pytest.raises(DatabaseError, match="newer version"):
        Database(path)


def test_file_that_is_not_a_database(tmp_path):
    path = tmp_path / "auth.db"
    path.write_text("this is not a database " * 50, encoding="utf-8")
    with pytest.raises(DatabaseError):
        Database(path)


def test_folder_in_the_way(tmp_path):
    with pytest.raises(DatabaseError, match="Could not open"):
        Database(tmp_path)


def test_bad_sql_becomes_a_database_error(db):
    with pytest.raises(DatabaseError):
        db.execute("SELECT * FROM no_such_table")


def test_integrity_errors_are_passed_on(db):
    db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")


def count_users(db) -> int:
    return db.query_one("SELECT COUNT(*) FROM users")[0]


class TestTransactions:
    def test_commit(self, db):
        with db.transaction():
            db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")
        assert count_users(db) == 1

    def test_error_undoes_everything(self, db):
        with pytest.raises(RuntimeError):
            with db.transaction():
                db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")
                raise RuntimeError("power cut")
        assert count_users(db) == 0

    def test_inner_transaction_joins_the_outer_one(self, db):
        with pytest.raises(RuntimeError):
            with db.transaction():
                with db.transaction():
                    db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")
                raise RuntimeError("outer fails after inner finished")
        assert count_users(db) == 0

    def test_can_be_used_again_after_a_rollback(self, db):
        with pytest.raises(RuntimeError):
            with db.transaction():
                raise RuntimeError
        with db.transaction():
            db.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES ('a', 'a@x.com', 'h', '2026-10-15')")
        assert count_users(db) == 1


def test_repr(db):
    assert repr(db) == "Database(':memory:')"
    assert db.path == ":memory:"
