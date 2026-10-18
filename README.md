# Authentication System

Sign up, log in, sessions and permissions, written in Python using only the
standard library. Passwords are never stored as they were typed.

Project 4 of a 12 week portfolio. Weeks 1 to 3 covered OOP, SOLID and a
SQLite database. This week is about doing security properly.

## Status

Day 4 of 7. Password hashing, password strength rules, users saved in SQLite,
signing up, logging in, account lockout, and login sessions.

## Getting started

```bash
python -m venv .venv
.venv\Scripts\activate           # macOS or Linux: source .venv/bin/activate
pip install -r requirements.txt  # only needed for the tests

pytest                           # run the tests
```

Needs Python 3.10 or newer.

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

## Tests

```bash
pytest          # 140 tests
```

The tests use a hasher with far fewer rounds so they run quickly. The real
default is never lowered.

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
