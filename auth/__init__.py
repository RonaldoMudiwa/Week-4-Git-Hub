"""Authentication System.

Sign up, log in and permissions, with passwords stored safely.

    from auth import PBKDF2Hasher, PasswordPolicy
"""

from .database import Database
from .exceptions import (
    AccountDisabledError,
    AccountLockedError,
    AuthError,
    InvalidCredentialsError,
    LoginError,
    DatabaseError,
    DuplicateError,
    NotFoundError,
    UserNotFoundError,
    ValidationError,
    WeakPasswordError,
)
from .lockout import LockoutPolicy
from .password_rules import (
    HasDigit,
    HasLowercase,
    HasSymbol,
    HasUppercase,
    MaximumLength,
    MinimumLength,
    NotCommon,
    NotPersonal,
    PasswordPolicy,
    PasswordRule,
)
from .passwords import PasswordHasher, PBKDF2Hasher
from .service import AuthService
from .user import User
from .users import SQLiteUserRepository, UserRepository

__version__ = "0.3.0"

__all__ = [
    "AuthService",
    "LockoutPolicy",
    "User",
    "UserRepository",
    "SQLiteUserRepository",
    "Database",
    "PasswordHasher",
    "PBKDF2Hasher",
    "PasswordPolicy",
    "PasswordRule",
    "MinimumLength",
    "MaximumLength",
    "HasUppercase",
    "HasLowercase",
    "HasDigit",
    "HasSymbol",
    "NotCommon",
    "NotPersonal",
    "AuthError",
    "ValidationError",
    "WeakPasswordError",
    "LoginError",
    "InvalidCredentialsError",
    "AccountLockedError",
    "AccountDisabledError",
    "NotFoundError",
    "UserNotFoundError",
    "DuplicateError",
    "DatabaseError",
    "__version__",
]
