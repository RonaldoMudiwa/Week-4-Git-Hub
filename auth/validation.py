"""Checks for usernames and emails."""

from __future__ import annotations

import re

from .exceptions import ValidationError

# Starts with a letter, then letters, numbers, dots, dashes or underscores.
USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{2,29}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def clean_username(value: object) -> str:
    """Lower-case and check a username. 3 to 30 characters."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Username can't be blank.")
    username = value.strip().lower()
    if not USERNAME_PATTERN.match(username):
        raise ValidationError(
            "Username must be 3 to 30 characters, start with a letter, and only use "
            "letters, numbers, dots, dashes and underscores."
        )
    return username


def clean_email(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Email can't be blank.")
    email = value.strip().lower()
    if len(email) > 254 or not EMAIL_PATTERN.match(email):
        raise ValidationError(f"{email!r} doesn't look like an email address.")
    return email
