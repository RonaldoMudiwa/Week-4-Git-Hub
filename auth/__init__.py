"""Authentication System.

Sign up, log in and permissions, with passwords stored safely.

    from auth import PBKDF2Hasher, PasswordPolicy
"""

from .admin import AdminService
from .audit import AuditEntry, AuditEvent, AuditLog, NullAuditLog, SQLiteAuditLog
from .database import Database
from .exceptions import (
    AccountDisabledError,
    AccountLockedError,
    AuthError,
    DatabaseError,
    DuplicateError,
    InvalidCredentialsError,
    InvalidSessionError,
    LoginError,
    NotFoundError,
    PermissionDeniedError,
    ResetTokenError,
    SessionError,
    SessionExpiredError,
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
from .permissions import (
    ADMIN,
    MODERATOR,
    USER,
    AccessControl,
    Permission,
    Role,
    RoleRegistry,
    RoleRepository,
    SQLiteRoleRepository,
    requires,
)
from .reset import ResetToken, ResetTokenRepository, SQLiteResetTokenRepository
from .service import AuthService
from .sessions import (
    Session,
    SessionManager,
    SessionPolicy,
    SessionRepository,
    SQLiteSessionRepository,
)
from .user import User
from .users import SQLiteUserRepository, UserRepository

__version__ = "0.6.0"

__all__ = [
    "AuthService",
    "LockoutPolicy",
    "AdminService",
    "AuditLog",
    "AuditEvent",
    "AuditEntry",
    "NullAuditLog",
    "SQLiteAuditLog",
    "ResetToken",
    "ResetTokenRepository",
    "SQLiteResetTokenRepository",
    "AccessControl",
    "Permission",
    "Role",
    "RoleRegistry",
    "RoleRepository",
    "SQLiteRoleRepository",
    "requires",
    "USER",
    "MODERATOR",
    "ADMIN",
    "SessionManager",
    "SessionPolicy",
    "Session",
    "SessionRepository",
    "SQLiteSessionRepository",
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
    "SessionError",
    "InvalidSessionError",
    "SessionExpiredError",
    "PermissionDeniedError",
    "ResetTokenError",
    "NotFoundError",
    "UserNotFoundError",
    "DuplicateError",
    "DatabaseError",
    "__version__",
]
