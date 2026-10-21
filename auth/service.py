"""AuthService: signing up, logging in, and changing or resetting passwords.

It joins the pieces together: the password rules, the hasher, the lockout
policy, the user store and the audit log. Each of those is passed in, so
any of them can be swapped, for example a faster hasher in tests.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Callable, ContextManager

from .audit import AuditEvent, AuditLog, NullAuditLog, SQLiteAuditLog
from .database import Database
from .exceptions import (
    AccountDisabledError,
    AccountLockedError,
    InvalidCredentialsError,
    ResetTokenError,
    UserNotFoundError,
    ValidationError,
)
from .lockout import LockoutPolicy
from .password_rules import PasswordPolicy
from .passwords import PasswordHasher, PBKDF2Hasher
from .permissions import ADMIN, USER, RoleRepository, SQLiteRoleRepository
from .reset import RESET_LIFETIME, ResetToken, ResetTokenRepository, SQLiteResetTokenRepository
from .sessions import TOKEN_BYTES, SessionManager, hash_token
from .user import User
from .users import SQLiteUserRepository, UserRepository
from .validation import clean_email, clean_username

Clock = Callable[[], datetime]
TransactionFactory = Callable[[], ContextManager[None]]

WRONG_DETAILS = "Wrong username or password."
BAD_RESET = "That reset link is wrong, already used, or has run out. Ask for a new one."


class AuthService:
    def __init__(
        self,
        users: UserRepository,
        roles: RoleRepository,
        resets: ResetTokenRepository,
        transaction: TransactionFactory,
        *,
        hasher: PasswordHasher | None = None,
        password_policy: PasswordPolicy | None = None,
        lockout: LockoutPolicy | None = None,
        sessions: SessionManager | None = None,
        audit: AuditLog | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._users = users
        self._roles = roles
        self._resets = resets
        self._transaction = transaction
        self._hasher = hasher or PBKDF2Hasher()
        self._policy = password_policy or PasswordPolicy.default()
        self._lockout = lockout or LockoutPolicy()
        self._sessions = sessions
        self._audit = audit or NullAuditLog()
        self._clock = clock or datetime.now
        self._dummy_hash: str | None = None

    @classmethod
    def open(cls, db: Database, clock: Clock | None = None, **options) -> "AuthService":
        """The normal setup, with everything kept in this database."""
        audit = SQLiteAuditLog(db, clock)
        options.setdefault("sessions", SessionManager.open(db, clock=clock, audit=audit))
        return cls(SQLiteUserRepository(db), SQLiteRoleRepository(db),
                   SQLiteResetTokenRepository(db), db.transaction,
                   audit=audit, clock=clock, **options)

    @property
    def now(self) -> datetime:
        return self._clock()

    # ------------------------------------------------------------------
    # Signing up
    # ------------------------------------------------------------------

    def register(self, username: str, email: str, password: str) -> User:
        """Create an account with the "user" role.

        The very first account also becomes an admin, so someone can manage
        the system from the start.

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
        with self._transaction():
            first = not self._users.all()
            self._users.add(user)
            self._roles.grant(user.user_id, USER.name, self.now)
            if first:
                self._roles.grant(user.user_id, ADMIN.name, self.now)
            self._audit.record(AuditEvent.REGISTERED, user, "first account, made admin" if first else "")
        return user

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
            # The typed name isn't logged, in case someone typed their password there.
            self._audit.record(AuditEvent.LOGIN_FAILED, None, "unknown account")
            raise InvalidCredentialsError(WRONG_DETAILS)

        now = self.now
        if user.is_locked(now):
            self._audit.record(AuditEvent.LOGIN_REFUSED, user, "account locked")
            raise AccountLockedError(self._locked_message(user))

        if not self._hasher.verify(password, user.password_hash):
            with self._transaction():
                just_locked = user.record_failed_login(now, self._lockout)
                self._users.update(user)
                self._audit.record(AuditEvent.LOGIN_FAILED, user, "wrong password")
                if just_locked:
                    self._audit.record(AuditEvent.ACCOUNT_LOCKED, user,
                                       f"until {user.locked_until:%H:%M}")
            # Raised after the with block, so the failed attempt is still saved.
            if just_locked:
                raise AccountLockedError(self._locked_message(user))
            raise InvalidCredentialsError(WRONG_DETAILS)

        # Only said once the password is right, so it doesn't help a guesser.
        if not user.is_active:
            self._audit.record(AuditEvent.LOGIN_REFUSED, user, "account switched off")
            raise AccountDisabledError("This account has been switched off. Contact an admin.")

        with self._transaction():
            user.record_successful_login(now)
            # Quietly upgrade old hashes while we have the real password.
            if self._hasher.needs_rehash(user.password_hash):
                user.set_password_hash(self._hasher.hash(password))
            self._users.update(user)
            self._audit.record(AuditEvent.LOGIN_OK, user)
        return user

    def login_with_session(self, name_or_email: str, password: str) -> tuple[User, str]:
        """Log in and start a session. Returns the user and their session token."""
        if self._sessions is None:
            raise ValidationError("This service was set up without sessions.")
        user = self.login(name_or_email, password)
        return user, self._sessions.start(user)

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    def change_password(self, user_id: int, current_password: str, new_password: str) -> User:
        """Change a password. The current one has to be given, so someone who
        finds a logged in computer can't lock the owner out. Every session is
        logged out afterwards."""
        user = self._users.get(user_id)
        if not self._hasher.verify(current_password, user.password_hash):
            raise InvalidCredentialsError("The current password is wrong.")
        if new_password == current_password:
            raise ValidationError("The new password must be different from the old one.")
        self._replace_password(user, new_password, AuditEvent.PASSWORD_CHANGED)
        return user

    def request_password_reset(self, email: str) -> str | None:
        """Make a one-time reset token for whoever owns this email.

        Returns the token, which a real system would email as a link. Returns
        None if no active account has that email. Whoever shows the result
        to the public must say the same thing either way ("if that email is
        registered, a link is on its way"), so it can't be used to find out
        who has an account.
        """
        user = self._users.find_by_email(email)
        if user is None or not user.is_active:
            return None
        now = self.now
        token = secrets.token_urlsafe(TOKEN_BYTES)
        with self._transaction():
            # Only the newest link should ever work.
            self._resets.cancel_unused(user.user_id, now)
            self._resets.add(ResetToken(user.user_id, hash_token(token), now, now + RESET_LIFETIME))
            self._audit.record(AuditEvent.RESET_REQUESTED, user)
        return token

    def reset_password(self, token: str, new_password: str) -> User:
        """Set a new password using a reset token. The token then stops
        working, the account is unlocked, and every session is logged out.

        Raises:
            ResetTokenError: The token is wrong, used or too old.
            WeakPasswordError: The new password breaks the rules.
        """
        if not isinstance(token, str) or not token:
            raise ResetTokenError(BAD_RESET)
        found = self._resets.find(hash_token(token))
        if found is None or not found.is_usable(self.now):
            raise ResetTokenError(BAD_RESET)
        user = self._users.get(found.user_id)
        with self._transaction():
            self._resets.mark_used(found.reset_id, self.now)
            user.unlock()
            self._replace_password(user, new_password, AuditEvent.PASSWORD_RESET)
        return user

    # ------------------------------------------------------------------

    def get_user(self, user_id: int) -> User:
        return self._users.get(user_id)

    def find_user(self, username: str) -> User:
        """Look someone up by username. Raises UserNotFoundError if there's no such user."""
        user = self._users.find_by_username(username)
        if user is None:
            raise UserNotFoundError(f"No user called {str(username).strip().lower()!r}.")
        return user

    @property
    def users(self) -> list[User]:
        return self._users.all()

    def _replace_password(self, user: User, new_password: str, event: AuditEvent) -> None:
        self._policy.check(new_password, personal=[user.username, user.email])
        with self._transaction():
            user.set_password_hash(self._hasher.hash(new_password))
            self._users.update(user)
            self._audit.record(event, user)
            if self._sessions is not None:
                self._sessions.end_all(user.user_id)

    def _fake_hash(self) -> str:
        if self._dummy_hash is None:
            self._dummy_hash = self._hasher.hash("not a real password")
        return self._dummy_hash

    @staticmethod
    def _locked_message(user: User) -> str:
        until = user.locked_until.strftime("%H:%M") if user.locked_until else "later"
        return f"Too many wrong passwords. Try again after {until}."
