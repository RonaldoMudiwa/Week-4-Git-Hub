"""Authentication System.

Sign up, log in and permissions, with passwords stored safely.

    from auth import PBKDF2Hasher, PasswordPolicy
"""

from .database import Database
from .exceptions import (
    AuthError,
    DatabaseError,
    DuplicateError,
    NotFoundError,
    UserNotFoundError,
    ValidationError,
    WeakPasswordError,
)
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
from .user import User
from .users import SQLiteUserRepository, UserRepository

__version__ = "0.2.0"

__all__ = [
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
    "NotFoundError",
    "UserNotFoundError",
    "DuplicateError",
    "DatabaseError",
    "__version__",
]
