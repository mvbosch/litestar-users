from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, TypeVar, runtime_checkable

from advanced_alchemy.base import ModelProtocol
from sqlalchemy.orm import Mapped, MappedClassProtocol

if TYPE_CHECKING:
    from uuid import UUID

__all__ = ["SQLAlchemyRoleProtocol", "SQLAlchemyUserProtocol"]


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


SQLARoleT = TypeVar("SQLARoleT", bound="SQLAlchemyRoleProtocol")
SQLAUserT = TypeVar("SQLAUserT", bound="SQLAlchemyUserProtocol | SQLAlchemyUserRoleProtocol")
