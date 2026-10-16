# Authentication System

Sign up, log in, sessions and permissions, written in Python using only the
standard library. Passwords are never stored as they were typed.

Project 4 of a 12 week portfolio. Weeks 1 to 3 covered OOP, SOLID and a
SQLite database. This week is about doing security properly.

## Status

Day 2 of 7. Password hashing, password strength rules, and users saved in SQLite.

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

## Tests

```bash
pytest          # 92 tests
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
