"""AuthService: signing up, logging in and changing passwords.

It joins the pieces together: the password rules, the hasher, the lockout
policy and the user store. Each of those is passed in, so any of them can
be swapped, for example a faster hasher in tests.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, ContextManager

from .database import Database
from .exceptions import (
    AccountDisabledError,
    AccountLockedError,
    InvalidCredentialsError,
    ValidationError,
)
from .lockout import LockoutPolicy
from .password_rules import PasswordPolicy
from .passwords import PasswordHasher, PBKDF2Hasher
from .user import User
from .users import SQLiteUserRepository, UserRepository
from .validation import clean_email, clean_username

Clock = Callable[[], datetime]
TransactionFactory = Callable[[], ContextManager[None]]

WRONG_DETAILS = "Wrong username or password."


class AuthService:
    def __init__(
        self,
        users: UserRepository,
        transaction: TransactionFactory,
        hasher: PasswordHasher | None = None,
        password_policy: PasswordPolicy | None = None,
        lockout: LockoutPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._users = users
        self._transaction = transaction
        self._hasher = hasher or PBKDF2Hasher()
        self._policy = password_policy or PasswordPolicy.default()
        self._lockout = lockout or LockoutPolicy()
        self._clock = clock or datetime.now
        self._dummy_hash: str | None = None

    @classmethod
    def open(cls, db: Database, **options) -> "AuthService":
        """The normal setup, with users kept in this database."""
        return cls(SQLiteUserRepository(db), db.transaction, **options)

    @property
    def now(self) -> datetime:
        return self._clock()

    # ------------------------------------------------------------------
    # Signing up
    # ------------------------------------------------------------------

    def register(self, username: str, email: str, password: str) -> User:
        """Create an account.

        Raises:
            ValidationError: If the username or email isn't allowed.
            WeakPasswordError: If the password breaks the rules. Lists them all.
            DuplicateError: If the username or email is taken.
        """
        # Check the cheap things first, so a bad username is reported before
        # spending time hashing the password.
        clean_name = clean_username(username)
        clean_mail = clean_email(email)
        self._policy.check(password, personal=[clean_name, clean_mail])
        user = User(clean_name, clean_mail, self._hasher.hash(password), self.now)
        return self._users.add(user)

    # ------------------------------------------------------------------
    # Logging in
    # ------------------------------------------------------------------

    def login(self, name_or_email: str, password: str) -> User:
        """Check a username (or email) and password.

        Raises:
            InvalidCredentialsError: Wrong username or password. The message
                is the same either way.
            AccountLockedError: Too many wrong passwords. Try again later.
            AccountDisabledError: The account has been switched off.
        """
        user = self._users.find_for_login(name_or_email)
        if user is None:
            # Still do the slow hash, so an unknown username takes as long
            # as a wrong password and timing can't reveal which it was.
            self._hasher.verify(str(password), self._fake_hash())
            raise InvalidCredentialsError(WRONG_DETAILS)

        now = self.now
        if user.is_locked(now):
            raise AccountLockedError(self._locked_message(user))

        if not self._hasher.verify(password, user.password_hash):
            with self._transaction():
                just_locked = user.record_failed_login(now, self._lockout)
                self._users.update(user)
            # Raised after the with block, so the failed attempt is still saved.
            if just_locked:
                raise AccountLockedError(self._locked_message(user))
            raise InvalidCredentialsError(WRONG_DETAILS)

        # Only said once the password is right, so it doesn't help a guesser.
        if not user.is_active:
            raise AccountDisabledError("This account has been switched off. Contact an admin.")

        with self._transaction():
            user.record_successful_login(now)
            # Quietly upgrade old hashes while we have the real password.
            if self._hasher.needs_rehash(user.password_hash):
                user.set_password_hash(self._hasher.hash(password))
            self._users.update(user)
        return user

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    def change_password(self, user_id: int, current_password: str, new_password: str) -> User:
        """Change a password. The current one has to be given, so someone who
        finds a logged in computer can't lock the owner out."""
        user = self._users.get(user_id)
        if not self._hasher.verify(current_password, user.password_hash):
            raise InvalidCredentialsError("The current password is wrong.")
        self._set_new_password(user, new_password, old_password=current_password)
        return user

    def unlock(self, user_id: int) -> User:
        user = self._users.get(user_id)
        user.unlock()
        self._users.update(user)
        return user

    def get_user(self, user_id: int) -> User:
        return self._users.get(user_id)

    @property
    def users(self) -> list[User]:
        return self._users.all()

    def _set_new_password(self, user: User, new_password: str,
                          old_password: str | None = None) -> None:
        if old_password is not None and new_password == old_password:
            raise ValidationError("The new password must be different from the old one.")
        self._policy.check(new_password, personal=[user.username, user.email])
        user.set_password_hash(self._hasher.hash(new_password))
        self._users.update(user)

    def _fake_hash(self) -> str:
        if self._dummy_hash is None:
            self._dummy_hash = self._hasher.hash("not a real password")
        return self._dummy_hash

    @staticmethod
    def _locked_message(user: User) -> str:
        until = user.locked_until.strftime("%H:%M") if user.locked_until else "later"
        return f"Too many wrong passwords. Try again after {until}."
