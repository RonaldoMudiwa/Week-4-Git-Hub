"""Hashing passwords so they're never stored as they were typed.

A hash is a one way scramble. "hunter2" always turns into the same jumble,
but the jumble can't be turned back into "hunter2". To check a password at
log in, we scramble what was typed and compare the two jumbles.

Two extra things make it much harder to crack:

- Salt: random bytes mixed in, different for every password. Two people
  with the same password get different hashes, so one cracked hash doesn't
  give away the other.
- Rounds: the scramble is repeated hundreds of thousands of times. That
  takes a fraction of a second for one log in, but makes guessing millions
  of passwords far too slow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod

from .exceptions import ValidationError

# What OWASP recommended for PBKDF2 with SHA-256 when this was written.
DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 16


class PasswordHasher(ABC):
    """Anything that can hash a password and check one later."""

    @abstractmethod
    def hash(self, password: str) -> str:
        """Return a string holding everything needed to check the password later."""

    @abstractmethod
    def verify(self, password: str, stored: str) -> bool:
        """True if password matches what hash() returned. Never raises for a
        wrong password, only returns False."""

    @abstractmethod
    def needs_rehash(self, stored: str) -> bool:
        """True if the stored hash used weaker settings than this hasher does now."""


class PBKDF2Hasher(PasswordHasher):
    """PBKDF2 with SHA-256, built into Python's hashlib.

    Stored as one string: "pbkdf2_sha256$600000$<salt>$<hash>". Keeping the
    rounds in the string means old hashes still check after the number of
    rounds goes up.
    """

    ALGORITHM = "pbkdf2_sha256"

    def __init__(self, iterations: int = DEFAULT_ITERATIONS) -> None:
        if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
            raise ValidationError("Iterations must be a whole number above zero.")
        self._iterations = iterations

    @property
    def iterations(self) -> int:
        return self._iterations

    def hash(self, password: str) -> str:
        _check_password_type(password)
        salt = secrets.token_bytes(SALT_BYTES)
        digest = self._digest(password, salt, self._iterations)
        return "$".join([self.ALGORITHM, str(self._iterations), _b64(salt), _b64(digest)])

    def verify(self, password: str, stored: str) -> bool:
        if not isinstance(password, str):
            return False
        parts = self._split(stored)
        if parts is None:
            return False
        iterations, salt, expected = parts
        actual = self._digest(password, salt, iterations)
        # compare_digest takes the same time whether the first byte or the
        # last byte differs, so timing can't leak how close a guess was.
        return hmac.compare_digest(actual, expected)

    def needs_rehash(self, stored: str) -> bool:
        parts = self._split(stored)
        return parts is None or parts[0] < self._iterations

    @staticmethod
    def _digest(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

    def _split(self, stored: str) -> tuple[int, bytes, bytes] | None:
        """Pull the rounds, salt and hash out of a stored string. None if it's damaged."""
        try:
            algorithm, iterations, salt, digest = stored.split("$")
            if algorithm != self.ALGORITHM:
                return None
            return int(iterations), _unb64(salt), _unb64(digest)
        except (AttributeError, ValueError):
            return None

    def __repr__(self) -> str:
        return f"PBKDF2Hasher(iterations={self._iterations})"


def _check_password_type(password: object) -> None:
    if not isinstance(password, str) or password == "":
        raise ValidationError("Password can't be empty.")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)
