"""The command line interface.

    python -m auth register ronaldo ronaldo@example.com
    python -m auth login ronaldo
    python -m auth whoami
    python -m auth logout

Passwords are always typed at a hidden prompt, never as part of the command,
so they don't end up in the terminal's history. Logging in saves the session
token in data/.session, so the next commands know who you are.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from abc import ABC, abstractmethod
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence, TextIO

from .admin import AdminService
from .audit import AuditEvent
from .database import Database
from .exceptions import AuthError, InvalidSessionError, SessionError, ValidationError
from .mail import FileMailer, Mailer
from .passwords import PasswordHasher
from .service import AuthService
from .sessions import SessionManager
from .user import User

DEFAULT_DATA = Path("data")
NOT_LOGGED_IN = "You're not logged in. Run: python -m auth login <username>"

AskPassword = Callable[[str], str]


class TokenStore:
    """Keeps the session token in a small file between commands.

    Like keeping a festival wristband on between gigs. The file is made
    readable by its owner only, where the system allows it.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def save(self, token: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(token, encoding="utf-8")
        try:
            os.chmod(self._path, 0o600)
        except OSError:  # pragma: no cover - some file systems don't allow it
            pass

    def load(self) -> str | None:
        try:
            return self._path.read_text(encoding="utf-8").strip() or None
        except FileNotFoundError:
            return None

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)


class Context:
    """What a command gets to work with while it runs."""

    def __init__(self, out: TextIO, ask_password: AskPassword, tokens: TokenStore,
                 auth: AuthService | None = None, sessions: SessionManager | None = None,
                 admin: AdminService | None = None, mailer: Mailer | None = None) -> None:
        self.out = out
        self.ask_password = ask_password
        self.tokens = tokens
        self._auth = auth
        self._sessions = sessions
        self._admin = admin
        self._mailer = mailer
        self.current_user: User | None = None

    @property
    def auth(self) -> AuthService:
        return self._need(self._auth)

    @property
    def sessions(self) -> SessionManager:
        return self._need(self._sessions)

    @property
    def admin(self) -> AdminService:
        return self._need(self._admin)

    @property
    def mailer(self) -> Mailer:
        return self._need(self._mailer)

    @property
    def me(self) -> User:
        """The logged in user. Only set for commands that need a log in."""
        return self._need(self.current_user)

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def new_password(self) -> str:
        """Ask twice, so a typo doesn't lock someone out of their own account."""
        first = self.ask_password("New password: ")
        if self.ask_password("Type it again: ") != first:
            raise ValidationError("The two passwords don't match.")
        return first

    @staticmethod
    def _need(value):
        if value is None:
            raise RuntimeError("This command was run without what it needs.")
        return value


class Command(ABC):
    """One thing the user can ask for. Each command is its own small class."""

    name = ""
    help = ""
    needs_login = False
    needs_database = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add this command's own options. Commands with none can skip it."""

    @abstractmethod
    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        """Do the job. Raise an AuthError if it can't be done."""


# ----------------------------------------------------------------------
# Accounts
# ----------------------------------------------------------------------

class RegisterCommand(Command):
    name = "register"
    help = "make a new account"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("username")
        parser.add_argument("email")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        user = ctx.auth.register(args.username, args.email, ctx.new_password())
        ctx.say(f"Account {user.username} created. You can log in now.")


class LoginCommand(Command):
    name = "login"
    help = "log in with your username or email"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("username", help="username or email")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        user, token = ctx.auth.login_with_session(args.username, ctx.ask_password("Password: "))
        ctx.tokens.save(token)
        ctx.say(f"Logged in as {user.username}.")


class LogoutCommand(Command):
    name = "logout"
    help = "log out"
    needs_login = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--everywhere", action="store_true",
                            help="also log out every other device")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        if args.everywhere:
            count = ctx.sessions.end_all(ctx.me.user_id)
            ctx.say(f"Logged out of {count} session(s).")
        else:
            ctx.sessions.end(ctx.tokens.load())
            ctx.say("Logged out.")
        ctx.tokens.clear()


class WhoAmICommand(Command):
    name = "whoami"
    help = "show who's logged in, and what they're allowed to do"
    needs_login = True

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        me = ctx.me
        access = ctx.admin.access
        ctx.say(f"{me.username} ({me.email})")
        ctx.say("Roles: " + ", ".join(role.name for role in access.roles_of(me)))
        allowed = sorted(p.value.replace("_", " ") for p in access.permissions_of(me))
        ctx.say("Can: " + ", ".join(allowed))


class ChangePasswordCommand(Command):
    name = "change-password"
    help = "change your password (you'll be logged out everywhere)"
    needs_login = True

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        current = ctx.ask_password("Current password: ")
        ctx.auth.change_password(ctx.me.user_id, current, ctx.new_password())
        ctx.tokens.clear()
        ctx.say("Password changed. Please log in again.")


class ForgotCommand(Command):
    name = "forgot"
    help = "get a reset code by email if you forgot your password"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("email")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        token = ctx.auth.request_password_reset(args.email)
        if token is not None:
            ctx.mailer.send(args.email, "Reset your password",
                            f"Your reset code is:\n\n    {token}\n\nIt works once, for one hour.\n"
                            f"Run: python -m auth reset <code>")
        # The same message either way, so nobody can use this to find out
        # whether an email has an account.
        ctx.say("If that email is registered, a reset code is on its way.")


class ResetCommand(Command):
    name = "reset"
    help = "set a new password using a reset code"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("code")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        user = ctx.auth.reset_password(args.code, ctx.new_password())
        ctx.say(f"Password reset for {user.username}. You can log in now.")


# ----------------------------------------------------------------------
# Admin
# ----------------------------------------------------------------------

class UsersCommand(Command):
    name = "users"
    help = "list every account (moderators and admins)"
    needs_login = True

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        now = ctx.auth.now
        ctx.say(f"{'Id':<5}{'Username':<20}{'Email':<30}{'Roles':<20}State")
        ctx.say("-" * 85)
        for user, roles in ctx.admin.list_users(ctx.me):
            state = ("off" if not user.is_active else "locked" if user.is_locked(now) else "ok")
            ctx.say(f"{user.user_id:<5}{user.username:<20}{user.email:<30}"
                    f"{', '.join(roles):<20}{state}")


class _RoleCommand(Command):
    """Shared by grant and revoke."""

    needs_login = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("username")
        parser.add_argument("role", help="user, moderator or admin")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        user = ctx.auth.find_user(args.username)
        changed = self.change(ctx.admin, ctx.me, user.user_id, args.role)
        ctx.say(self.message(user.username, args.role, changed))

    @abstractmethod
    def change(self, admin: AdminService, actor: User, user_id: int, role: str) -> bool:
        """Make the change. Returns False if nothing needed doing."""

    @abstractmethod
    def message(self, username: str, role: str, changed: bool) -> str:
        """What to tell the user afterwards."""


class GrantCommand(_RoleCommand):
    name = "grant"
    help = "give someone a role (admins)"

    def change(self, admin: AdminService, actor: User, user_id: int, role: str) -> bool:
        return admin.grant_role(actor, user_id, role)

    def message(self, username: str, role: str, changed: bool) -> str:
        return f"{username} is now {role}." if changed else f"{username} was already {role}."


class RevokeCommand(_RoleCommand):
    name = "revoke"
    help = "take a role away from someone (admins)"

    def change(self, admin: AdminService, actor: User, user_id: int, role: str) -> bool:
        return admin.revoke_role(actor, user_id, role)

    def message(self, username: str, role: str, changed: bool) -> str:
        return f"{username} is no longer {role}." if changed else f"{username} wasn't {role}."


class _AccountCommand(Command):
    """Shared by deactivate, activate and unlock."""

    needs_login = True
    done = ""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("username")

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        user = ctx.auth.find_user(args.username)
        self.change(ctx.admin, ctx.me, user.user_id)
        ctx.say(f"{user.username} is {self.done}.")

    @abstractmethod
    def change(self, admin: AdminService, actor: User, user_id: int) -> None:
        """Make the change."""


class DeactivateCommand(_AccountCommand):
    name = "deactivate"
    help = "switch an account off (moderators and admins)"
    done = "switched off"

    def change(self, admin: AdminService, actor: User, user_id: int) -> None:
        admin.deactivate(actor, user_id)


class ActivateCommand(_AccountCommand):
    name = "activate"
    help = "switch an account back on (moderators and admins)"
    done = "switched on"

    def change(self, admin: AdminService, actor: User, user_id: int) -> None:
        admin.activate(actor, user_id)


class UnlockCommand(_AccountCommand):
    name = "unlock"
    help = "lift a lockout early (moderators and admins)"
    done = "unlocked"

    def change(self, admin: AdminService, actor: User, user_id: int) -> None:
        admin.unlock(actor, user_id)


class AuditCommand(Command):
    name = "audit"
    help = "read the audit log (admins)"
    needs_login = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--user", help="only this username")
        parser.add_argument("--event", choices=[e.value for e in AuditEvent])
        parser.add_argument("--limit", type=int, default=30)

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        user_id = ctx.auth.find_user(args.user).user_id if args.user else None
        event = AuditEvent(args.event) if args.event else None
        entries = ctx.admin.audit_log(ctx.me, args.limit, user_id, event)
        if not entries:
            ctx.say("Nothing in the log yet.")
        for entry in entries:
            ctx.say(str(entry))


class DemoCommand(Command):
    name = "demo"
    help = "a short tour with made up users (your real accounts aren't touched)"
    needs_database = False

    def run(self, ctx: Context, args: argparse.Namespace) -> None:
        from . import demo  # only loaded when someone asks for it

        with redirect_stdout(ctx.out):
            demo.main()


def default_commands() -> list[Command]:
    return [
        RegisterCommand(), LoginCommand(), LogoutCommand(), WhoAmICommand(),
        ChangePasswordCommand(), ForgotCommand(), ResetCommand(),
        UsersCommand(), GrantCommand(), RevokeCommand(),
        DeactivateCommand(), ActivateCommand(), UnlockCommand(), AuditCommand(),
        DemoCommand(),
    ]


class AuthCLI:
    """Reads what was typed and runs the matching command.

    The clock, hasher, password prompt and output are passed in, so tests
    can run every command without a keyboard or a real wait.
    """

    def __init__(
        self,
        commands: Sequence[Command] | None = None,
        clock: Callable[[], datetime] | None = None,
        hasher: PasswordHasher | None = None,
        ask_password: AskPassword | None = None,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        self._clock = clock
        self._hasher = hasher
        self._ask_password = ask_password or getpass.getpass
        self._out = out or sys.stdout
        self._err = err or sys.stderr
        self._commands: dict[str, Command] = {}
        for command in (commands if commands is not None else default_commands()):
            if command.name in self._commands:
                raise ValueError(f"Two commands are called {command.name!r}.")
            self._commands[command.name] = command

    @property
    def command_names(self) -> tuple[str, ...]:
        return tuple(self._commands)

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="python -m auth",
                                         description="Accounts, log in and permissions.")
        parser.add_argument("--data", type=Path, default=DEFAULT_DATA,
                            help=f"folder for the database, session and outbox (default: {DEFAULT_DATA})")
        subparsers = parser.add_subparsers(dest="command", required=True, metavar="command")
        for command in self._commands.values():
            sub = subparsers.add_parser(command.name, help=command.help, description=command.help)
            command.add_arguments(sub)
        return parser

    def run(self, argv: Sequence[str] | None = None) -> int:
        """Run one command. Returns 0 if it worked, 1 if it was refused.

        Typing mistakes are caught by argparse, which exits with 2.
        """
        args = self.build_parser().parse_args(argv)
        command = self._commands[args.command]
        tokens = TokenStore(args.data / ".session")
        try:
            if not command.needs_database:
                command.run(Context(self._out, self._ask_password, tokens), args)
                return 0
            with Database(args.data / "auth.db") as db:
                ctx = self._context(db, args.data, tokens)
                if command.needs_login:
                    ctx.current_user = self._logged_in_user(ctx)
                command.run(ctx, args)
        except AuthError as error:
            print(f"Error: {error}", file=self._err)
            return 1
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.", file=self._err)
            return 1
        return 0

    def _context(self, db: Database, data: Path, tokens: TokenStore) -> Context:
        options = {"hasher": self._hasher} if self._hasher else {}
        auth = AuthService.open(db, self._clock, **options)
        return Context(self._out, self._ask_password, tokens, auth,
                       SessionManager.open(db, clock=self._clock),
                       AdminService.open(db, self._clock),
                       FileMailer(data / "outbox.txt", self._clock))

    @staticmethod
    def _logged_in_user(ctx: Context) -> User:
        token = ctx.tokens.load()
        if token is None:
            raise InvalidSessionError(NOT_LOGGED_IN)
        try:
            return ctx.sessions.authenticate(token)
        except SessionError:
            # The saved token is no use any more, so forget it.
            ctx.tokens.clear()
            raise


def main(argv: Sequence[str] | None = None) -> int:
    return AuthCLI().run(argv)
