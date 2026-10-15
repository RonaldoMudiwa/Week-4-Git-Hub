"""All the errors this package can raise.

Everything inherits from AuthError, so one except clause catches the lot.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base class for every error in this package. Never raised directly."""


class ValidationError(AuthError):
    """A value isn't allowed, e.g. a blank username."""


class WeakPasswordError(ValidationError):
    """The password breaks one or more of the password rules.

    problems lists every rule it broke, so the user can fix them all at once
    instead of one at a time.
    """

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("Password is too weak: " + "; ".join(self.problems) + ".")
