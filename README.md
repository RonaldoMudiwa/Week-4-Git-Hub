# Authentication System

Sign up, log in, sessions and permissions, written in Python using only the
standard library. Passwords are never stored as they were typed.

Project 4 of a 12 week portfolio. Weeks 1 to 3 covered OOP, SOLID and a
SQLite database. This week is about doing security properly.

## Status

Finished. 222 tests with 100% line and branch coverage.

## What it can do

- Sign up with a password that has to pass sensible strength rules
- Store passwords as salted, slow hashes, never as typed
- Log in with a username or email, with lockout after repeated wrong passwords
- Keep people logged in with session tokens that time out
- Give users roles, and check permissions before anything sensitive runs
- Reset a forgotten password with a one-time code
- Keep an audit log of every security event
- Do all of the above from the terminal

## Getting started

```bash
python -m venv .venv
.venv\Scripts\activate           # macOS or Linux: source .venv/bin/activate
pip install -r requirements.txt  # only needed for the tests

python -m auth --help            # see every command
python -m auth demo              # a quick tour with made up users
pytest                           # run the tests
```

Needs Python 3.10 or newer.

## Using it from the terminal

```bash
python -m auth register ronaldo ronaldo@example.com    # asks for the password twice
python -m auth login ronaldo
python -m auth whoami                                  # your roles and what you can do
python -m auth change-password
python -m auth logout --everywhere

python -m auth forgot ronaldo@example.com              # the code lands in data/outbox.txt
python -m auth reset <code>

python -m auth users                                   # moderators and admins
python -m auth grant amara moderator                   # admins
python -m auth deactivate tendai
python -m auth unlock tendai
python -m auth audit --user amara --limit 20
```

The first account made is the admin. Passwords are always typed at a
hidden prompt, never as part of the command, so they don't end up in the
terminal's history. Logging in saves the session token (never the
password) in `data/.session`, readable only by you where the system allows
it. There's no real email, so `forgot` writes the email to
`data/outbox.txt`. Swapping in a real email service only means a new
`Mailer` class. Use `--data other_folder` before the command to keep a
separate set of accounts.

## Storing passwords

```python
from auth import PBKDF2Hasher

hasher = PBKDF2Hasher()
stored = hasher.hash("Purple-Hibiscus-2003")
# 'pbkdf2_sha256$600000$Qm9i...$x7Kd...'

hasher.verify("Purple-Hibiscus-2003", stored)   # True
hasher.verify("purple-hibiscus-2003", stored)   # False
```

- **Hashed, not encrypted.** A hash can't be turned back into the password,
  even by us. To check a log in, the typed password is hashed the same way
  and the two hashes are compared.
- **Salted.** 16 random bytes are mixed into every password, so two people
  with the same password get different hashes.
- **Slow on purpose.** PBKDF2 repeats the hash 600,000 times. One log in
  barely notices, but someone trying millions of guesses is slowed right down.
- **Compared in constant time.** `hmac.compare_digest` takes the same time
  however close a guess is, so timing gives nothing away.
- **Ready for the future.** The number of rounds is saved with each hash,
  so it can be raised later. `needs_rehash()` says when an old hash should be
  upgraded.

## Password rules

```python
from auth import PasswordPolicy

policy = PasswordPolicy.default()
policy.problems("abc")
# ['use at least 12 characters', 'add a capital letter', 'add a number', 'add a symbol such as ! or #']
policy.check("Purple-Hibiscus-2003", personal=["ronaldo"])   # passes
```

| Rule | Checks |
| --- | --- |
| `MinimumLength(12)` | Long enough |
| `MaximumLength(128)` | Not so long that hashing it is slow |
| `HasUppercase`, `HasLowercase`, `HasDigit`, `HasSymbol` | A mix of characters |
| `NotCommon` | Not on the list of passwords hackers try first |
| `NotPersonal` | Doesn't contain the username or email |

Every problem is listed at once, so the user can fix them together. Each
rule is its own class, so a new rule is a new class added to the list.

## Users

```python
from auth import Database, SQLiteUserRepository, User

with Database("data/auth.db") as db:
    users = SQLiteUserRepository(db)
    users.find_for_login("Ronaldo@Example.com")   # by email or username, any case
```

- Usernames are 3 to 30 characters, start with a letter, and are saved in
  lower case. Emails are checked and lower-cased too.
- `User` only ever holds the password's hash. Its `repr()` leaves the hash
  out, so it can't leak into a log by accident.
- The database makes usernames and emails `UNIQUE COLLATE NOCASE`, so
  "Ronaldo" and "ronaldo" can never be two accounts.
- The database code follows the same pattern as Week 3: numbered
  migrations, transactions, and `?` placeholders for every value.

## Signing up and logging in

```python
from auth import AuthService, Database

with Database("data/auth.db") as db:
    service = AuthService.open(db)
    service.register("ronaldo", "ronaldo@example.com", "Purple-Hibiscus-2003")
    user = service.login("Ronaldo@Example.com", "Purple-Hibiscus-2003")
    service.change_password(user.user_id, "Purple-Hibiscus-2003", "Half-Of-A-Yellow-Sun-2006")
```

Things it does to stay safe:

- **Same answer for a wrong username or a wrong password.** Both say "Wrong
  username or password." If it said "no such user", an attacker could find
  out which usernames are real.
- **Same time too.** An unknown username still runs the slow hash, so it
  takes as long as a wrong password.
- **Lockout.** 5 wrong passwords in a row lock the account for 15 minutes.
  The count resets after a good log in. An admin can unlock early. Both
  numbers can be changed with `LockoutPolicy`.
- **Switched off accounts.** Only revealed once the right password is given.
- **Automatic upgrades.** If the number of hashing rounds goes up, old hashes
  are re-hashed the next time that person logs in.
- **Changing a password needs the current one**, and the new one has to pass
  the rules and be different.

The hasher, password rules, lockout policy and clock are all passed in to
`AuthService`, so tests can use a quick hasher and pretend time has passed.

## Sessions

Typing a password for every action would be a pain, so after logging in the
user gets a session token instead. It works like a festival wristband: show
it to get in, and it stops working when it runs out or is cut off.

```python
from auth import SessionManager

sessions = SessionManager.open(db)
token = sessions.start(user)          # give this to the user
sessions.authenticate(token)          # -> the User, and resets the idle timer
sessions.end(token)                   # log out here
sessions.end_all(user.user_id)        # log out everywhere
```

- **Tokens are random.** 32 bytes from `secrets`, which is made for security.
  `random` is predictable and is never used for this.
- **Only a hash is stored.** If the database leaked, the hashes couldn't be
  used to log in. A quick SHA-256 is fine here, because random tokens can't
  be guessed from a list the way passwords can.
- **Two time limits.** 30 minutes with no activity, or 12 hours in total,
  whichever comes first. Both can be changed with `SessionPolicy`.
- **Switching an account off logs it out**, even from sessions already open.
- **Tidy up.** `purge()` deletes sessions that finished more than 30 days ago.

## Roles and permissions

A permission is one thing someone can do. A role is a named bundle of them.
Code only ever checks permissions, never role names, so roles can change
without touching the checks.

| Role | Can |
| --- | --- |
| `user` | See their own profile and change their own password |
| `moderator` | Everything a user can, plus see every account and switch accounts off, on and unlock them |
| `admin` | Everything, including giving out roles and reading the audit log |

```python
from auth import AdminService, Permission, requires

admin = AdminService.open(db)
admin.grant_role(ronaldo, amara.user_id, "moderator")
admin.deactivate(amara, tendai.user_id)        # amara is now allowed to do this

class Reports:
    @requires(Permission.VIEW_USERS)           # checked before the method runs
    def everyone(self, actor): ...
```

- Every new account gets `user`. The very first account also gets `admin`,
  so someone can run the system from the start.
- `@requires` is a decorator, so the check can't be forgotten inside the
  method. It runs first, every time.
- The last admin can't lose the admin role, or nobody could manage roles
  again. Nobody can switch off their own account, and a moderator can't
  switch off an admin.
- A switched off account has no permissions at all, whatever its roles.
- New roles can be added to a `RoleRegistry` without changing any code that
  checks permissions.

## Forgotten passwords

```python
token = service.request_password_reset("ronaldo@example.com")   # a real app emails this as a link
service.reset_password(token, "Half-Of-A-Yellow-Sun-2006")
```

- The token is random and only its hash is stored, like sessions.
- It works once, for one hour. Asking again cancels the older link.
- A wrong, used or old token all give the same message.
- An unknown email returns `None` instead of an error. Whatever shows this
  to the public should say "if that email is registered, a link is on its
  way" either way, so nobody can use it to check who has an account.
- Resetting unlocks the account. Resetting or changing a password logs the
  user out everywhere, in case someone else was logged in as them.

## Audit log

Every sign up, log in, failed log in, lockout, log out, password change,
reset and admin action is written to the `audit_log` table with the time and
who it was about. Admins can read it:

```python
for entry in admin.audit_log(ronaldo, limit=20):
    print(entry)
# 2026-10-15 09:00:00  login_failed          amara  wrong password
```

Passwords and tokens are never written to the log. When someone tries to log
in as a name that doesn't exist, the name isn't written either, because
people sometimes type their password into the username box by mistake.
Code that records events never checks whether there is a log: a
`NullAuditLog` that does nothing is used when no log is wanted.

## How it's built

```
auth/
├── cli.py              The terminal commands
├── demo.py             The quick tour behind "python -m auth demo"
├── service.py          AuthService: sign up, log in, change and reset passwords
├── admin.py            AdminService: users, roles, switching accounts off, the audit log
├── sessions.py         Session tokens, time limits and logging out
├── permissions.py      Permissions, roles and the @requires decorator
├── passwords.py        Hashing and checking passwords
├── password_rules.py   Password strength rules
├── lockout.py          How many wrong passwords before a lock
├── reset.py            One-time password reset codes
├── audit.py            The audit log
├── mail.py             Sending emails (to a file for now)
├── user.py             A user account
├── users.py            Saving and finding users
├── database.py         Opening SQLite, setting up tables, transactions
├── validation.py       Username and email checks
└── exceptions.py       Every error the package can raise
```

| Table | Holds |
| --- | --- |
| `users` | Accounts, with the password hash, lockout count and state |
| `sessions` | A hash of each session token, with its time limits |
| `user_roles` | Which roles each user has |
| `reset_tokens` | A hash of each reset code, when it runs out and if it's used |
| `audit_log` | Every security event, kept even if the user is later deleted |

### OOP and SOLID

- **Abstraction.** `PasswordHasher`, `PasswordRule`, every repository,
  `AuditLog` and `Mailer` are abstract. The rest of the code only uses them.
- **Encapsulation.** A user's password hash, lockout count and lock time
  only change through their own methods. `repr()` never shows the hash.
- **Inheritance and polymorphism.** Each password rule, mailer and command
  is a subclass the rest of the code treats the same way.
- **Single responsibility.** Hashing, rules, lockout, sessions, roles, the
  log and email each live in their own module.
- **Open/closed.** A new password rule, role, mailer or terminal command is
  a new class. Nothing that uses them changes.
- **Liskov substitution.** `NullAuditLog` and `MemoryMailer` can stand in for
  the real ones anywhere.
- **Interface segregation.** Users, sessions, roles and reset codes each
  have their own small repository.
- **Dependency inversion.** The services are handed their hasher, rules,
  repositories, log and clock. Tests pass in a quick hasher and a fake clock.

### Security choices, in one place

| Risk | What stops it |
| --- | --- |
| Stolen database reveals passwords | Salted PBKDF2 with 600,000 rounds |
| Stolen database lets someone log in | Session and reset tokens are stored only as hashes |
| Guessing passwords online | Lockout after 5 wrong tries, strength rules, common password list |
| Finding out who has an account | Same message and same timing for wrong user or wrong password, same reply to `forgot` |
| Timing attacks on hash checks | `hmac.compare_digest` |
| Predictable tokens | `secrets`, never `random` |
| Sessions that never end | Idle and total time limits, log out everywhere |
| Someone else logged in as you | Changing or resetting a password logs out every session |
| SQL injection | `?` placeholders for every value |
| Secrets in logs | The audit log never records passwords, tokens or unknown usernames |
| Doing things you shouldn't | `@requires` checks permissions before the method runs |

## Tests

```bash
pytest                 # 222 tests
pytest --cov           # the same, plus a coverage report
```

Coverage settings live in `.coveragerc`, and the run fails below 95%. The
tests use a hasher with far fewer rounds so they run quickly. The real
default is never lowered. A `FakeClock` lets lockouts, timeouts and expiry
be tested without waiting, and the terminal tests type passwords with a
fake keyboard.

| File | What it checks |
| --- | --- |
| `test_passwords.py`, `test_password_rules.py` | Hashing and the strength rules |
| `test_users.py`, `test_database.py` | Users, tables and transactions |
| `test_login.py` | Sign up, log in, lockout, rehashing, changing passwords |
| `test_sessions.py` | Tokens, time limits and logging out |
| `test_permissions.py` | Roles, permissions, `@requires` and admin actions |
| `test_reset_and_audit.py` | Reset codes and the audit log |
| `test_mail.py` | The mailers |
| `test_cli.py` | Every terminal command |

## Week plan

| Day | Focus |
| --- | --- |
| 1 | Password hashing and password rules |
| 2 | Users, saved in SQLite |
| 3 | Sign up, log in and account lockout |
| 4 | Login sessions with expiry and log out |
| 5 | Roles and permissions |
| 6 | Password reset and an audit log |
| 7 | Command line interface, final tests and README |

All seven days are done.
