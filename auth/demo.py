"""A quick tour with made up users. Run it from the project root:

    python -m auth demo

It uses a database in memory and a pretend clock, so it never touches your
real accounts and can show 15 minutes going by straight away. It also uses
fewer hashing rounds than the real thing, so it finishes quickly.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .admin import AdminService
from .database import Database
from .exceptions import AuthError
from .passwords import PBKDF2Hasher
from .service import AuthService
from .sessions import SessionManager


class PretendClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 21, 9, 0)

    def __call__(self) -> datetime:
        return self.now

    def skip(self, minutes: int) -> None:
        self.now += timedelta(minutes=minutes)
        print(f"\n... {minutes} minutes later ({self.now:%H:%M}) ...")


def main() -> None:
    clock = PretendClock()
    with Database() as db:
        auth = AuthService.open(db, clock, hasher=PBKDF2Hasher(iterations=20_000))
        sessions = SessionManager.open(db, clock=clock)
        admin = AdminService.open(db, clock)

        print("Signing up")
        try:
            auth.register("amara", "amara@example.com", "password1")
        except AuthError as error:
            print(f"  amara tries 'password1': {error}")
        ronaldo = auth.register("ronaldo", "ronaldo@example.com", "Purple-Hibiscus-2003")
        amara = auth.register("amara", "amara@example.com", "Half-Of-A-Yellow-Sun-2006")
        print(f"  {ronaldo.username} signs up first, so he's an admin")
        print(f"  {amara.username} signs up with a stronger password")
        print(f"  Stored for ronaldo: {ronaldo.password_hash[:45]}...")

        print("\nLogging in")
        _, token = auth.login_with_session("ronaldo", "Purple-Hibiscus-2003")
        print(f"  ronaldo logs in and gets a session token: {token[:12]}...")
        print(f"  The token says this is: {sessions.authenticate(token).username}")

        print("\nSomeone guesses amara's password")
        for guess in ("amara123", "Amara2026!", "letmein", "qwerty", "hunter2"):
            try:
                auth.login("amara", guess)
            except AuthError as error:
                print(f"  {guess!r}: {error}")
        try:
            auth.login("amara", "Half-Of-A-Yellow-Sun-2006")
        except AuthError as error:
            print(f"  Even the right password now: {error}")
        clock.skip(15)
        auth.login("amara", "Half-Of-A-Yellow-Sun-2006")
        print("  amara logs in fine once the lock runs out")

        print("\nPermissions")
        try:
            admin.list_users(amara)
        except AuthError as error:
            print(f"  amara tries to list users: {error}")
        admin.grant_role(ronaldo, amara.user_id, "moderator")
        print(f"  ronaldo makes amara a moderator, now she sees "
              f"{len(admin.list_users(amara))} accounts")

        print("\nForgotten password")
        code = auth.request_password_reset("amara@example.com")
        auth.reset_password(code, "Things-Fall-Apart-1958")
        print("  amara resets her password with a one-time code")

        print("\nThe audit log (newest first)")
        for entry in admin.audit_log(ronaldo, limit=8):
            print(f"  {entry}")
