"""Tests for the password rules."""

from __future__ import annotations

import pytest

from auth import (
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
    ValidationError,
    WeakPasswordError,
)

STRONG = "Purple-Hibiscus-2003"


def test_strong_password_passes():
    PasswordPolicy.default().check(STRONG)
    assert PasswordPolicy.default().problems(STRONG) == []


def test_every_problem_is_listed_at_once():
    problems = PasswordPolicy.default().problems("abc")
    assert "use at least 12 characters" in problems
    assert "add a capital letter" in problems
    assert "add a number" in problems
    assert "add a symbol such as ! or #" in problems
    assert "add a small letter" not in problems


def test_check_raises_with_every_problem():
    with pytest.raises(WeakPasswordError) as raised:
        PasswordPolicy.default().check("abc")
    assert len(raised.value.problems) == 4
    assert str(raised.value).startswith("Password is too weak: use at least 12 characters;")


@pytest.mark.parametrize("rule, bad, good", [
    (MinimumLength(5), "abcd", "abcde"),
    (MaximumLength(5), "abcdef", "abcde"),
    (HasUppercase(), "abc", "aBc"),
    (HasLowercase(), "ABC", "AbC"),
    (HasDigit(), "abc", "ab3"),
    (HasSymbol(), "abc", "a!c"),
    (HasSymbol(), "abc", "a c"),
])
def test_each_rule(rule, bad, good):
    assert rule.problem(bad) is not None
    assert rule.problem(good) is None


@pytest.mark.parametrize("password", ["password", "PASSWORD", "Password1!", "qwerty123", "letmein!!"])
def test_common_passwords_are_refused(password):
    assert NotCommon().problem(password) is not None


def test_custom_common_list():
    rule = NotCommon(["Mudiwa2026"])
    assert rule.problem("mudiwa2026") is not None
    assert rule.problem("password") is None


def test_personal_details_are_refused():
    rule = NotPersonal()
    assert rule.problem("Ronaldo-2026!x", ("ronaldo", "r.m@example.com")) is not None
    assert rule.problem("my-ro-password", ("ro",)) is None  # too short to count
    assert rule.problem("my-amara.okafor-pw", ("amara.okafor@example.com",)) is not None
    assert rule.problem(STRONG, ("ronaldo",)) is None


def test_policy_passes_personal_details_on():
    policy = PasswordPolicy.default()
    assert policy.problems("Ronaldo-Rocks-26", personal=["ronaldo"]) == \
        ["don't use your username or email in your password"]
    assert policy.problems(STRONG, personal=["", None]) == []


def test_a_custom_policy():
    policy = PasswordPolicy([MinimumLength(4)])
    assert policy.problems("abcd") == []
    assert len(policy.rules) == 1


def test_a_new_rule_can_be_added_without_changing_the_others():
    class NoSpaces(PasswordRule):
        def problem(self, password, personal=()):
            return "remove the spaces" if " " in password else None

    policy = PasswordPolicy([*PasswordPolicy.default().rules, NoSpaces()])
    assert policy.problems("Purple Hibiscus 2003") == ["remove the spaces"]


def test_non_text_password():
    assert PasswordPolicy.default().problems(None) == ["the password must be text"]


def test_bad_policy_setup():
    with pytest.raises(ValidationError):
        PasswordPolicy(["not a rule"])
    with pytest.raises(ValidationError):
        MinimumLength(0)
