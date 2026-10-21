"""Sending emails, such as password reset links.

The program only uses Mailer, so a real email service could be plugged in
later. For now FileMailer writes each email to a text file instead, which
is enough to try the reset flow on one computer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Callable

from .exceptions import AuthError


class Mailer(ABC):
    @abstractmethod
    def send(self, to: str, subject: str, body: str) -> None:
        """Send one email."""


class FileMailer(Mailer):
    """Adds each email to the end of a text file, like an outbox."""

    def __init__(self, path: str | Path, clock: Callable[[], datetime] | None = None) -> None:
        self._path = Path(path)
        self._clock = clock or datetime.now

    @property
    def path(self) -> Path:
        return self._path

    def send(self, to: str, subject: str, body: str) -> None:
        text = (f"Date: {self._clock():%Y-%m-%d %H:%M}\nTo: {to}\nSubject: {subject}\n\n"
                f"{body}\n{'-' * 60}\n")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as outbox:
                outbox.write(text)
        except OSError as error:
            raise AuthError(f"Could not write to {self._path}: {error}") from error


class MemoryMailer(Mailer):
    """Keeps emails in a list. Used in tests and the demo."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []

    def send(self, to: str, subject: str, body: str) -> None:
        self.sent.append((to, subject, body))
