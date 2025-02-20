from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.exceptions import NotFoundError
from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig
from litestar.exceptions import ImproperlyConfiguredException
from sqlalchemy.orm import Load

from litestar_users.utils import get_litestar_users_plugin, get_sqlalchemy_plugin

__all__ = ["jwt_retrieve_user_handler", "session_retrieve_user_handler"]


if TYPE_CHECKING:
    from advanced_alchemy.repository import LoadSpec
    from litestar.connection import ASGIConnection
    from litestar.security.jwt import Token

    from litestar_users.adapter.sqlalchemy.protocols import SQLAUserT
    from litestar_users.adapter.sqlalchemy.repository import SQLAlchemyUserRepository


def _get_user_repository(connection: ASGIConnection) -> SQLAlchemyUserRepository:
    sqlalchemy_config = get_sqlalchemy_plugin(connection.app).config[0]
    if not isinstance(sqlalchemy_config, SQLAlchemyAsyncConfig):
        raise ImproperlyConfiguredException("SQLAlchemy config must be of type `SQLAlchemyAsyncConfig`")
    async_session = sqlalchemy_config.provide_session(state=connection.app.state, scope=connection.scope)

    litestar_users_config = get_litestar_users_plugin(connection.app)._config
    return litestar_users_config.user_repository_class(
        session=async_session,
        model_type=litestar_users_config.user_model,
        auto_commit=litestar_users_config.auto_commit_transactions,
    )


def _get_load_options(connection: ASGIConnection) -> LoadSpec | None:
    load_options = connection.route_handler.opt.get("user_load_options")
    if load_options is None:
        return None
    if not isinstance(load_options, Sequence):
        raise ValueError("user_load_options must be a sequence")
    if not all(isinstance(load_option, Load) for load_option in load_options):
        raise ValueError("all load options must be instances of `sqlalchemy.orm.Load`")
    return load_options


async def session_retrieve_user_handler(session: dict[str, Any], connection: ASGIConnection) -> SQLAUserT | None:
    """Get a user from the database based on session info.

    Args:
        session: Litestar session.
        connection: The ASGI connection.
    """
    repository = _get_user_repository(connection)
    try:
        user_id = session.get("user_id")
        if user_id is None:
            return None
        try:
            user_id = UUID(user_id)
        except ValueError:
            user_id = int(user_id)
        user = await repository.get(user_id, load=_get_load_options(connection))
        if user.is_active and user.is_verified:
            return user  # type: ignore[no-any-return]
    except NotFoundError:
        pass
    return None


async def jwt_retrieve_user_handler(token: Token, connection: ASGIConnection) -> SQLAUserT | None:
    """Get a user from the database based on JWT info.

    Args:
        token: Encoded JWT.
        connection: The ASGI connection.
    """
    repository = _get_user_repository(connection)
    try:
        user_id: UUID | int | None = None
        try:
            user_id = UUID(token.sub)
        except ValueError:
            user_id = int(token.sub)
        user = await repository.get(user_id, load=_get_load_options(connection))
        if user.is_active and user.is_verified:
            return user  # type: ignore[no-any-return]
    except NotFoundError:
        pass
    return None
