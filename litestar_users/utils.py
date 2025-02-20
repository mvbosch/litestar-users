from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyInitPlugin
from litestar.exceptions import ImproperlyConfiguredException
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from litestar_users.adapter.sqlalchemy.repository import SQLAlchemyRoleRepository

if TYPE_CHECKING:
    from litestar import Litestar
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_users import LitestarUsersPlugin
    from litestar_users.service import BaseUserService


def get_litestar_users_plugin(app: Litestar) -> LitestarUsersPlugin:
    """Get the LitestarUsersPlugin from the Litestar application."""
    from litestar_users import LitestarUsersPlugin

    try:
        return app.plugins.get(LitestarUsersPlugin)
    except KeyError as e:
        raise ImproperlyConfiguredException("The LitestarUsersPlugin is missing from the application") from e


def get_sqlalchemy_plugin(app: Litestar) -> SQLAlchemyInitPlugin:
    """Get the SQLAlchemyPlugin from the Litestar application."""
    try:
        return app.plugins.get(SQLAlchemyInitPlugin)
    except KeyError as e:
        raise ImproperlyConfiguredException("The SQLAlchemyPlugin is missing from the application") from e


@asynccontextmanager
async def async_session(app: Litestar) -> AsyncIterator[AsyncSession]:
    """Get an async session outside of a Litestar request context."""

    sqlalchemy_config = get_sqlalchemy_plugin(app)._config
    if isinstance(sqlalchemy_config, Sequence):
        raise ImproperlyConfiguredException("Multiple SQLAlchemy configurations are not currently supported")
    engine = sqlalchemy_config.get_engine()
    if not isinstance(engine, AsyncEngine):
        raise ImproperlyConfiguredException("The SQLAlchemy engine must be async")
    sessionmaker = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with sessionmaker() as session:
        yield session


def get_user_service(app: Litestar, session: AsyncSession) -> BaseUserService[Any, Any]:
    """Get a `UserService` instance outside of a Litestar request context."""

    config = get_litestar_users_plugin(app)._config

    user_repository = config.user_repository_class(session, config.user_model)
    role_repository: SQLAlchemyRoleRepository | None = (
        SQLAlchemyRoleRepository(session, config.role_model) if config.role_model else None
    )
    return config.user_service_class(
        user_auth_identifier=config.user_auth_identifier,
        user_repository=user_repository,
        role_repository=role_repository,
        secret=config.secret,
        hash_schemes=config.hash_schemes,
    )
