"""Tests for the command line interface.

Each test gets its own data folder in tmp_path, and passwords are typed by
a fake keyboard, so nothing real is touched.
"""

from __future__ import annotations

import argparse
import io
import re
import runpy
import sys

import pytest

from auth.cli import AuthCLI, Command, Context, TokenStore, default_commands, main

from .conftest import STRONG

NEW = "Half-Of-A-Yellow-Sun-2006"


class Terminal:
    def __init__(self, data, clock, hasher) -> None:
        self.data = data
        self.clock = clock
        self.hasher = hasher

    def run(self, *argv: str, passwords=(), commands=None) -> tuple[int, str, str]:
        typed = list(passwords)
        prompts = []

        def keyboard(prompt: str) -> str:
            prompts.append(prompt)
            return typed.pop(0)

        out, err = io.StringIO(), io.StringIO()
        cli = AuthCLI(commands=commands, clock=self.clock, hasher=self.hasher,
                      ask_password=keyboard, out=out, err=err)
        code = cli.run(["--data", str(self.data), *argv])
        assert typed == [], "not every password was asked for"
        self.prompts = prompts
        return code, out.getvalue(), err.getvalue()

    def ok(self, *argv: str, **kwargs) -> str:
        code, out, err = self.run(*argv, **kwargs)
        assert code == 0, err
        return out

    def fails(self, *argv: str, **kwargs) -> str:
        code, out, err = self.run(*argv, **kwargs)
        assert code == 1, out
        return err

    def register(self, name: str) -> None:
        self.ok("register", name, f"{name}@example.com", passwords=[STRONG, STRONG])

    def login(self, name: str, password: str = STRONG) -> None:
        self.ok("login", name, passwords=[password])


@pytest.fixture
def term(tmp_path, clock, fast_hasher) -> Terminal:
    return Terminal(tmp_path / "data", clock, fast_hasher)


@pytest.fixture
def team(term) -> Terminal:
    """ronaldo (admin) and amara (user). Nobody is logged in."""
    term.register("ronaldo")
    term.register("amara")
    return term


class TestAccounts:
    def test_register_asks_for_the_password_twice(self, term):
        out = term.ok("register", "ronaldo", "ronaldo@example.com", passwords=[STRONG, STRONG])
        assert "Account ronaldo created" in out
        assert term.prompts == ["New password: ", "Type it again: "]

    def test_passwords_that_dont_match(self, term):
        err = term.fails("register", "ronaldo", "r@example.com", passwords=[STRONG, NEW])
        assert "don't match" in err

    def test_weak_password(self, term):
        assert "too weak" in term.fails("register", "ronaldo", "r@example.com",
                                        passwords=["weak", "weak"])

    def test_login_whoami_logout(self, team):
        assert "Logged in as ronaldo" in team.ok("login", "ronaldo", passwords=[STRONG])
        out = team.ok("whoami")
        assert "ronaldo (ronaldo@example.com)" in out
        assert "Roles: admin, user" in out
        assert "manage roles" in out
        assert "Logged out." in team.ok("logout")
        assert "not logged in" in team.fails("whoami")

    def test_session_file_holds_the_token_not_the_password(self, team):
        team.login("ronaldo")
        saved = (team.data / ".session").read_text(encoding="utf-8")
        assert STRONG not in saved and len(saved) >= 40

    def test_wrong_password(self, team):
        assert "Wrong username or password" in team.fails("login", "ronaldo", passwords=["nope"])

    def test_logout_everywhere(self, team):
        team.login("ronaldo")
        team.login("ronaldo")
        assert "Logged out of 2 session(s)" in team.ok("logout", "--everywhere")

    def test_timed_out_session_is_forgotten(self, team, clock):
        team.login("ronaldo")
        clock.advance(minutes=31)
        assert "timed out" in team.fails("whoami")
        assert not (team.data / ".session").exists()
        assert "not logged in" in team.fails("whoami")

    def test_change_password(self, team):
        team.login("amara")
        out = team.ok("change-password", passwords=[STRONG, NEW, NEW])
        assert "Please log in again" in out
        assert "not logged in" in team.fails("whoami")
        team.login("amara", NEW)

    def test_change_password_needs_the_current_one(self, team):
        team.login("amara")
        assert "current password is wrong" in team.fails("change-password",
                                                          passwords=["nope", NEW, NEW])


class TestForgottenPasswords:
    def test_reset_code_arrives_in_the_outbox(self, team):
        out = team.ok("forgot", "amara@example.com")
        assert "If that email is registered" in out
        outbox = (team.data / "outbox.txt").read_text(encoding="utf-8")
        assert "To: amara@example.com" in outbox
        code = re.search(r"code is:\s+(\S+)", outbox).group(1)

        assert "Password reset for amara" in team.ok("reset", code, passwords=[NEW, NEW])
        team.login("amara", NEW)
        assert "run out" in team.fails("reset", code, passwords=[NEW, NEW])

    def test_unknown_email_gets_the_same_message_and_no_email(self, team):
        out = team.ok("forgot", "nobody@example.com")
        assert "If that email is registered" in out
        assert not (team.data / "outbox.txt").exists()


class TestAdmin:
    def test_users_list(self, team):
        team.login("ronaldo")
        out = team.ok("users")
        assert "amara" in out and "admin, user" in out

    def test_plain_user_is_refused(self, team):
        team.login("amara")
        assert "isn't allowed" in team.fails("users")
        assert "isn't allowed" in team.fails("grant", "amara", "admin")

    def test_grant_and_revoke(self, team):
        team.login("ronaldo")
        assert "amara is now moderator" in team.ok("grant", "amara", "moderator")
        assert "already moderator" in team.ok("grant", "amara", "moderator")
        assert "no longer moderator" in team.ok("revoke", "amara", "moderator")
        assert "wasn't moderator" in team.ok("revoke", "amara", "moderator")
        assert "Unknown role" in team.fails("grant", "amara", "king")
        assert "No user called 'ghost'" in team.fails("grant", "ghost", "admin")

    def test_switch_off_and_on(self, team):
        team.login("ronaldo")
        assert "amara is switched off" in team.ok("deactivate", "amara")
        assert "off" in team.ok("users").splitlines()[-1]
        assert "switched off" in team.fails("login", "amara", passwords=[STRONG])
        team.login("ronaldo")
        assert "amara is switched on" in team.ok("activate", "amara")

    def test_unlock(self, team):
        for _ in range(5):
            team.fails("login", "amara", passwords=["nope"])
        team.login("ronaldo")
        assert "locked" in team.ok("users").splitlines()[-1]
        assert "amara is unlocked" in team.ok("unlock", "amara")
        team.login("amara")

    def test_audit_log(self, team):
        team.fails("login", "amara", passwords=["nope"])
        team.login("ronaldo")
        out = team.ok("audit")
        assert "login_failed" in out and "registered" in out
        assert "ronaldo" not in team.ok("audit", "--user", "amara")
        only = team.ok("audit", "--event", "login_failed")
        assert "registered" not in only
        assert len(team.ok("audit", "--limit", "1").splitlines()) == 1

    def test_empty_audit_filter(self, team):
        team.login("ronaldo")
        assert "Nothing in the log yet." in team.ok("audit", "--event", "password_reset")


class TestRunning:
    def test_demo_makes_no_files(self, term):
        out = term.ok("demo")
        assert "The audit log" in out
        assert not term.data.exists()

    def test_typing_mistakes_exit_with_2(self, term, capsys):
        for argv in ([], ["login"], ["audit", "--event", "party"], ["fly"]):
            with pytest.raises(SystemExit) as stopped:
                term.run(*argv)
            assert stopped.value.code == 2

    def test_ctrl_c_at_a_password_prompt(self, term):
        def interrupted(prompt):
            raise KeyboardInterrupt

        err = io.StringIO()
        cli = AuthCLI(ask_password=interrupted, out=io.StringIO(), err=err)
        assert cli.run(["--data", str(term.data), "login", "ronaldo"]) == 1
        assert "Cancelled." in err.getvalue()

    def test_main_and_python_dash_m(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        assert main(["whoami"]) == 1
        assert (tmp_path / "data" / "auth.db").exists()
        monkeypatch.setattr(sys, "argv", ["auth", "--data", str(tmp_path / "d"), "forgot",
                                          "x@example.com"])
        with pytest.raises(SystemExit) as stopped:
            runpy.run_module("auth", run_name="__main__")
        assert stopped.value.code == 0
        assert "If that email" in capsys.readouterr().out


class TestPieces:
    def test_token_store(self, tmp_path):
        store = TokenStore(tmp_path / "x" / ".session")
        assert store.load() is None
        store.save("abc")
        assert store.load() == "abc"
        store.clear()
        store.clear()
        assert store.load() is None

    def test_a_new_command_works_without_editing_the_cli(self, team):
        class PingCommand(Command):
            name = "ping"
            help = "check the program runs"
            needs_login = True

            def run(self, ctx: Context, args: argparse.Namespace) -> None:
                ctx.say(f"pong, {ctx.me.username}")

        team.login("amara")
        assert team.ok("ping", commands=[*default_commands(), PingCommand()]).strip() == "pong, amara"

    def test_two_commands_with_one_name(self):
        with pytest.raises(ValueError, match="login"):
            AuthCLI(commands=[*default_commands(), default_commands()[1]])

    def test_every_command_has_help(self):
        assert len(AuthCLI().command_names) == len(default_commands())
        assert all(c.name and c.help for c in default_commands())

    def test_context_without_services(self):
        ctx = Context(io.StringIO(), input, TokenStore(None))
        for name in ("auth", "sessions", "admin", "mailer", "me"):
            with pytest.raises(RuntimeError):
                getattr(ctx, name)
