"""How many wrong passwords are allowed before an account is paused."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .exceptions import ValidationError


@dataclass(frozen=True)
class LockoutPolicy:
    """After max_attempts wrong passwords in a row, lock for lock_for.

    Like a phone that makes you wait after too many wrong PINs. It stops
    someone trying thousands of passwords, but a real user who mistypes a
    few times only waits a short while.
    """

    max_attempts: int = 5
    lock_for: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) \
                or self.max_attempts < 1:
            raise ValidationError("max_attempts must be a whole number above zero.")
        if not isinstance(self.lock_for, timedelta) or self.lock_for <= timedelta(0):
            raise ValidationError("lock_for must be a length of time above zero.")
