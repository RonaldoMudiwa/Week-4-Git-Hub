"""Tests for User and saving users."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from auth import (
    DuplicateError,
    SQLiteUserRepository,
    User,
    UserNotFoundError,
    ValidationError,
)

NOW = datetime(2026, 10, 15, 9, 0)


def make(**changes) -> User:
    details = {"username": "Ronaldo", "email": "Ronaldo@Example.com",
               "password_hash": "pbkdf2_sha256$1$a$b", "created_at": NOW}
    details.update(changes)
    return User(**details)


class TestUser:
    def test_details_are_tidied(self):
        user = make()
        assert user.username == "ronaldo"
        assert user.email == "ronaldo@example.com"
        assert user.is_active
        assert user.failed_logins == 0
        assert user.user_id is None

    @pytest.mark.parametrize("username", ["ab", "1ronaldo", "ron aldo", "ron!", "", None, "a" * 31])
    def test_bad_usernames(self, username):
        with pytest.raises(ValidationError):
            make(username=username)

    @pytest.mark.parametrize("username", ["abc", "ronaldo.mudiwa", "r_m-2026", "a" * 30])
    def test_good_usernames(self, username):
        assert make(username=username).username == username

    @pytest.mark.parametrize("changes", [
        {"email": "nope"},
        {"email": ""},
        {"email": "a@" + "b" * 260 + ".com"},
        {"password_hash": ""},
        {"created_at": "2026-10-15"},
        {"failed_logins": -1},
        {"failed_logins": True},
        {"user_id": 0},
    ])
    def test_bad_values(self, changes):
        with pytest.raises(ValidationError):
            make(**changes)

    def test_locked(self):
        user = make(locked_until=NOW + timedelta(minutes=15))
        assert user.is_locked(NOW)
        assert not user.is_locked(NOW + timedelta(minutes=15))
        assert not make().is_locked(NOW)

    def test_activate_and_deactivate(self):
        user = make()
        user.deactivate()
        assert not user.is_active
        user.activate()
        assert user.is_active

    def test_id_only_once(self):
        user = make()
        user.assign_id(4)
        with pytest.raises(ValidationError):
            user.assign_id(5)

    def test_repr_never_shows_the_hash(self):
        user = make(user_id=2)
        assert "pbkdf2" not in repr(user)
        assert repr(user) == "User('ronaldo', 'ronaldo@example.com', user_id=2)"
        assert str(user) == "ronaldo"

    def test_equal_by_username(self):
        assert make() == make(email="other@example.com")
        assert make() != "ronaldo"
        assert len({make(), make(username="RONALDO")}) == 1


@pytest.fixture
def users(db) -> SQLiteUserRepository:
    return SQLiteUserRepository(db)


class TestRepository:
    def test_add_and_get_keep_everything(self, users):
        user = make(failed_logins=2, locked_until=NOW + timedelta(minutes=5),
                    last_login_at=NOW - timedelta(days=1))
        users.add(user)
        loaded = users.get(user.user_id)
        assert loaded.username == "ronaldo"
        assert loaded.failed_logins == 2
        assert loaded.locked_until == NOW + timedelta(minutes=5)
        assert loaded.last_login_at == NOW - timedelta(days=1)
        assert loaded.created_at == NOW
        assert loaded.password_hash == user.password_hash

    def test_username_and_email_must_be_unique(self, users):
        users.add(make())
        with pytest.raises(DuplicateError, match="username ronaldo is already taken"):
            users.add(make(email="new@example.com"))
        with pytest.raises(DuplicateError, match="email ronaldo@example.com"):
            users.add(make(username="someone"))

    def test_saved_user_cannot_be_added_again(self, users):
        with pytest.raises(ValidationError):
            users.add(users.add(make()))

    def test_find_by_username_or_email_in_any_case(self, users):
        users.add(make())
        assert users.find_by_username("RONALDO").email == "ronaldo@example.com"
        assert users.find_by_email(" RONALDO@example.com ").username == "ronaldo"
        assert users.find_for_login("Ronaldo@Example.com").username == "ronaldo"
        assert users.find_for_login("ronaldo").username == "ronaldo"
        assert users.find_for_login("nobody") is None
        assert users.find_by_email("nobody@example.com") is None

    def test_update(self, users):
        user = users.add(make())
        user.email = "new@example.com"
        user.set_password_hash("pbkdf2_sha256$2$c$d")
        user.deactivate()
        users.update(user)
        loaded = users.get(user.user_id)
        assert (loaded.email, loaded.password_hash, loaded.is_active) == \
            ("new@example.com", "pbkdf2_sha256$2$c$d", False)

    def test_update_to_a_taken_email(self, users):
        users.add(make())
        other = users.add(make(username="amara", email="amara@example.com"))
        other.email = "ronaldo@example.com"
        with pytest.raises(DuplicateError, match="email"):
            users.update(other)

    def test_update_needs_a_saved_user(self, users):
        with pytest.raises(ValidationError):
            users.update(make())
        with pytest.raises(UserNotFoundError):
            users.update(make(user_id=9))

    def test_missing_user(self, users):
        with pytest.raises(UserNotFoundError):
            users.get(1)

    def test_all_oldest_first(self, users):
        users.add(make(username="zara", email="z@example.com"))
        users.add(make(username="ade", email="a@example.com"))
        assert [u.username for u in users.all()] == ["zara", "ade"]

    def test_tricky_text_is_stored_safely(self, users):
        users.add(make())
        assert users.find_by_username("x' OR '1'='1") is None
