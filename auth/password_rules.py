"""Rules a new password has to pass.

Each rule is its own small class with one job. A PasswordPolicy runs a list
of them and collects every problem, so the user sees them all at once.
Adding a rule means writing a new class, not editing the others.
"""

from __future__ import annotations

import string
from abc import ABC, abstractmethod
from typing import Iterable

from .exceptions import ValidationError, WeakPasswordError

# A short list of passwords that get guessed first. A real system would use
# a much bigger list, such as the "Have I Been Pwned" one.
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwerty123", "abc123", "letmein", "welcome", "welcome1",
    "iloveyou", "admin", "admin123", "monkey", "football", "dragon", "sunshine",
    "princess", "passw0rd", "p@ssw0rd", "trustno1", "baseball", "master", "superman",
})


class PasswordRule(ABC):
    """One check. Returns a problem in plain words, or None if it passes."""

    @abstractmethod
    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        """personal holds things like the username, which shouldn't be in the password."""


class MinimumLength(PasswordRule):
    def __init__(self, length: int = 12) -> None:
        if isinstance(length, bool) or not isinstance(length, int) or length < 1:
            raise ValidationError("Length must be a whole number above zero.")
        self.length = length

    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        if len(password) < self.length:
            return f"use at least {self.length} characters"
        return None


class MaximumLength(PasswordRule):
    """Very long passwords are fine, but not megabytes of text that make hashing slow."""

    def __init__(self, length: int = 128) -> None:
        self.length = length

    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        if len(password) > self.length:
            return f"use no more than {self.length} characters"
        return None


class HasUppercase(PasswordRule):
    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        return None if any(c.isupper() for c in password) else "add a capital letter"


class HasLowercase(PasswordRule):
    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        return None if any(c.islower() for c in password) else "add a small letter"


class HasDigit(PasswordRule):
    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        return None if any(c.isdigit() for c in password) else "add a number"


class HasSymbol(PasswordRule):
    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        if any(c in string.punctuation or c == " " for c in password):
            return None
        return "add a symbol such as ! or #"


class NotCommon(PasswordRule):
    def __init__(self, common: Iterable[str] = COMMON_PASSWORDS) -> None:
        self._common = frozenset(word.lower() for word in common)

    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        # "Password1!" is still basically "password1".
        stripped = password.lower().rstrip("!@#$%^&*?.")
        if password.lower() in self._common or stripped in self._common:
            return "pick something less common, this one is on lists hackers try first"
        return None


class NotPersonal(PasswordRule):
    """The password mustn't contain the username or the name part of the email."""

    def problem(self, password: str, personal: tuple[str, ...] = ()) -> str | None:
        lowered = password.lower()
        for item in personal:
            word = item.lower().split("@")[0]
            if len(word) >= 3 and word in lowered:
                return "don't use your username or email in your password"
        return None


class PasswordPolicy:
    """Runs a set of rules on a password.

        >>> PasswordPolicy.default().problems("short")
        ['use at least 12 characters', 'add a capital letter', ...]
    """

    def __init__(self, rules: Iterable[PasswordRule]) -> None:
        self._rules = tuple(rules)
        if not all(isinstance(rule, PasswordRule) for rule in self._rules):
            raise ValidationError("Every rule must be a PasswordRule.")

    @classmethod
    def default(cls) -> "PasswordPolicy":
        return cls([MinimumLength(12), MaximumLength(128), HasUppercase(), HasLowercase(),
                    HasDigit(), HasSymbol(), NotCommon(), NotPersonal()])

    @property
    def rules(self) -> tuple[PasswordRule, ...]:
        return self._rules

    def problems(self, password: str, personal: Iterable[str] = ()) -> list[str]:
        """Every rule the password breaks. Empty if it's fine."""
        if not isinstance(password, str):
            return ["the password must be text"]
        extra = tuple(p for p in personal if p)
        found = (rule.problem(password, extra) for rule in self._rules)
        return [p for p in found if p]

    def check(self, password: str, personal: Iterable[str] = ()) -> None:
        """Raise WeakPasswordError listing every problem, if there are any."""
        problems = self.problems(password, personal)
        if problems:
            raise WeakPasswordError(problems)
