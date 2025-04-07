from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, TypeVar, runtime_checkable

from advanced_alchemy.base import ModelProtocol
from sqlalchemy.orm import Mapped, MappedClassProtocol

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

__all__ = ["SQLAlchemyOAuthAccountProtocol", "SQLAlchemyRoleProtocol", "SQLAlchemyUserProtocol"]


@runtime_checkable
class SQLAlchemyOAuthAccountProtocol(ModelProtocol, MappedClassProtocol, Protocol):  # pyright: ignore
    """The base SQLAlchemy OAuth account type."""

    id: Mapped[UUID] | Mapped[int]
    user_id: Mapped[UUID] | Mapped[int]
    oauth_name: Mapped[str]
    access_token: Mapped[str]
    account_id: Mapped[str]
    account_email: Mapped[str]
    expires_at: Mapped[datetime]
    refresh_token: Mapped[str]


@runtime_checkable
class SQLAlchemyRoleProtocol(ModelProtocol, MappedClassProtocol, Protocol):  # pyright: ignore
    """The base SQLAlchemy role type."""

    id: Mapped[UUID] | Mapped[int]
    name: Mapped[str]
    description: Mapped[str]


@runtime_checkable
class SQLAlchemyUserProtocol(ModelProtocol, MappedClassProtocol, Protocol):  # pyright: ignore
    """The base SQLAlchemy user type."""

    id: Mapped[UUID] | Mapped[int]
    email: Mapped[str]
    password_hash: Mapped[str]
    is_active: Mapped[bool]
    is_verified: Mapped[bool]

    def __init__(*args: Any, **kwargs: Any) -> None: ...


@runtime_checkable
class SQLAlchemyUserRoleProtocol(SQLAlchemyUserProtocol, Protocol):  # pyright: ignore
    """The base SQLAlchemy user type."""

    roles: Mapped[list[SQLAlchemyRoleProtocol]]


@runtime_checkable
class SQLAlchemyOAuth2UserProtocol(SQLAlchemyUserProtocol, Protocol):  # pyright: ignore
    """The base SQLAlchemy OAuth account type."""

    oauth_accounts: Mapped[list[SQLAlchemyOAuthAccountProtocol]]


@runtime_checkable
class SQLAlchemyOAuth2UserRoleProtocol(SQLAlchemyUserRoleProtocol, SQLAlchemyOAuth2UserProtocol, Protocol):  # pyright: ignore
    """The base SQLAlchemy OAuth account type."""


SQLARoleT = TypeVar("SQLARoleT", bound="SQLAlchemyRoleProtocol")
SQLAOAuthAccountT = TypeVar("SQLAOAuthAccountT", bound="SQLAlchemyOAuthAccountProtocol")
SQLAUserT = TypeVar(
    "SQLAUserT",
    bound="SQLAlchemyUserProtocol | SQLAlchemyUserRoleProtocol | SQLAlchemyOAuth2UserProtocol | SQLAlchemyOAuth2UserRoleProtocol",
)
