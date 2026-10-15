"""Tests for password hashing."""

from __future__ import annotations

import pytest

from auth import PBKDF2Hasher, ValidationError
from auth.passwords import DEFAULT_ITERATIONS


def test_hash_is_not_the_password(fast_hasher):
    stored = fast_hasher.hash("Correct Horse 9!")
    assert "Correct Horse" not in stored
    assert stored.startswith("pbkdf2_sha256$1000$")


def test_right_password_matches(fast_hasher):
    stored = fast_hasher.hash("Correct Horse 9!")
    assert fast_hasher.verify("Correct Horse 9!", stored)


@pytest.mark.parametrize("guess", ["correct horse 9!", "Correct Horse 9", "", "Correct Horse 9!!"])
def test_wrong_password_does_not_match(fast_hasher, guess):
    assert not fast_hasher.verify(guess, fast_hasher.hash("Correct Horse 9!"))


def test_same_password_gets_a_different_hash_each_time(fast_hasher):
    # Different salt every time.
    assert fast_hasher.hash("Correct Horse 9!") != fast_hasher.hash("Correct Horse 9!")


def test_unicode_passwords(fast_hasher):
    stored = fast_hasher.hash("pässwörd £ 東京 9A")
    assert fast_hasher.verify("pässwörd £ 東京 9A", stored)


def test_old_hashes_still_work_after_rounds_go_up():
    old = PBKDF2Hasher(iterations=1_000).hash("Correct Horse 9!")
    newer = PBKDF2Hasher(iterations=2_000)
    assert newer.verify("Correct Horse 9!", old)
    assert newer.needs_rehash(old)
    assert not newer.needs_rehash(newer.hash("Correct Horse 9!"))


@pytest.mark.parametrize("stored", [
    "",
    "nonsense",
    "md5$1000$abc$def",
    "pbkdf2_sha256$lots$abc$def",
    "pbkdf2_sha256$1000$not base64!$def",
    None,
])
def test_damaged_hash_never_matches(fast_hasher, stored):
    assert not fast_hasher.verify("anything", stored)
    assert fast_hasher.needs_rehash(stored)


def test_password_must_be_text(fast_hasher):
    assert not fast_hasher.verify(None, fast_hasher.hash("x"))
    with pytest.raises(ValidationError):
        fast_hasher.hash("")
    with pytest.raises(ValidationError):
        fast_hasher.hash(None)


@pytest.mark.parametrize("iterations", [0, -5, 1.5, True, "1000"])
def test_bad_iterations(iterations):
    with pytest.raises(ValidationError):
        PBKDF2Hasher(iterations=iterations)


def test_default_is_strong():
    assert PBKDF2Hasher().iterations == DEFAULT_ITERATIONS >= 600_000
    assert repr(PBKDF2Hasher(5)) == "PBKDF2Hasher(iterations=5)"
