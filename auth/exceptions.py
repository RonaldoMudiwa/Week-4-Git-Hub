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


class NotFoundError(AuthError):
    """Something asked for by id doesn't exist."""


class UserNotFoundError(NotFoundError):
    """No user has that id, username or email."""


class DuplicateError(AuthError):
    """A username or email is already taken."""


class DatabaseError(AuthError):
    """The database couldn't be opened or used."""


class LoginError(AuthError):
    """Logging in didn't work. Catch this for every reason at once."""


class InvalidCredentialsError(LoginError):
    """Wrong username or password.

    The message never says which one was wrong. Saying "no such user" would
    tell an attacker which usernames are real.
    """


class AccountLockedError(LoginError):
    """Too many wrong passwords in a row, so the account is paused for a while."""


class AccountDisabledError(LoginError):
    """An admin has switched this account off."""


class SessionError(AuthError):
    """A session token can't be used. Catch this for every reason at once."""


class InvalidSessionError(SessionError):
    """The token doesn't match any session, or it was logged out."""


class SessionExpiredError(SessionError):
    """The session ran out of time. Log in again."""


class PermissionDeniedError(AuthError):
    """The user is logged in but isn't allowed to do this."""


class ResetTokenError(AuthError):
    """A password reset link is wrong, used already, or too old.

    One message for all three, so a guesser learns nothing.
    """
