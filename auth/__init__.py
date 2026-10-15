"""Authentication System.

Sign up, log in and permissions, with passwords stored safely.

    from auth import PBKDF2Hasher, PasswordPolicy
"""

from .exceptions import AuthError, ValidationError, WeakPasswordError
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

__version__ = "0.1.0"

__all__ = [
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
    "__version__",
]
