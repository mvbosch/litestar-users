from __future__ import annotations

from typing import TYPE_CHECKING, cast

from passlib.context import CryptContext

if TYPE_CHECKING:
    from collections.abc import Sequence


__all__ = ["PasswordManager"]


class PasswordManager:
    """Thin wrapper around `passlib`."""

    def __init__(self, hash_schemes: Sequence[str] | None = None) -> None:
        """Construct a PasswordManager.

        Args:
            hash_schemes: The encryption schemes to use. Defaults to ["argon2"].
        """
        if hash_schemes is None:
            hash_schemes = ["argon2"]
        self.context = CryptContext(schemes=hash_schemes, deprecated="auto")

    def hash(self, password: str) -> str:
        """Create a password hash.

        Args:
            password: The password to hash.
        """
        return cast("str", self.context.hash(password))

    def verify_and_update(self, password: str, password_hash: str | None) -> tuple[bool, str | None]:
        """Verify a password and rehash it if the hash is deprecated.

        Args:
            password: The password to verify.
            password_hash: The hash to verify against.
        """
        return cast("tuple[bool, str | None]", self.context.verify_and_update(password, password_hash))
