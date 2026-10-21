"""Tests for the mailers."""

from __future__ import annotations

import pytest

from auth import AuthError, FileMailer, MemoryMailer


def test_file_mailer_adds_to_the_outbox(tmp_path, clock):
    mailer = FileMailer(tmp_path / "box" / "outbox.txt", clock)
    mailer.send("a@example.com", "Hello", "First")
    mailer.send("b@example.com", "Hi", "Second")
    text = mailer.path.read_text(encoding="utf-8")
    assert text.count("Subject:") == 2
    assert "Date: 2026-10-15 09:00" in text


def test_file_mailer_cannot_write(tmp_path):
    with pytest.raises(AuthError, match="Could not write"):
        FileMailer(tmp_path).send("a@example.com", "Hello", "Body")


def test_memory_mailer():
    mailer = MemoryMailer()
    mailer.send("a@example.com", "Hello", "Body")
    assert mailer.sent == [("a@example.com", "Hello", "Body")]
