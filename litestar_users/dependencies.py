from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig
from litestar.exceptions import ImproperlyConfiguredException

from litestar_users.adapter.sqlalchemy.repository import SQLAlchemyRoleRepository
from litestar_users.utils import get_litestar_users_plugin, get_sqlalchemy_plugin

__all__ = ["provide_user_service"]


if TYPE_CHECKING:
    from litestar import Request
    from litestar.datastructures import State

    from litestar_users.service import BaseUserService


def provide_user_service(state: State, request: Request) -> BaseUserService:
    """Instantiate service and repository for use with DI.

    Args:
        request: The incoming request
        state: The application.state instance
    """

    sqlalchemy_config = get_sqlalchemy_plugin(request.app).config[0]
    if not isinstance(sqlalchemy_config, SQLAlchemyAsyncConfig):
        raise ImproperlyConfiguredException("SQLAlchemy config must be of type `SQLAlchemyAsyncConfig`")
    session = sqlalchemy_config.provide_session(state=state, scope=request.scope)

    litestar_users_config = get_litestar_users_plugin(request.app)._config
    user_repository = litestar_users_config.user_repository_class(
        session=session,
        model_type=litestar_users_config.user_model,
        auto_commit=litestar_users_config.auto_commit_transactions,
    )
    role_repository: SQLAlchemyRoleRepository | None = (
        None
        if litestar_users_config.role_model is None
        else SQLAlchemyRoleRepository(
            session=session,
            model_type=litestar_users_config.role_model,
            auto_commit=litestar_users_config.auto_commit_transactions,
        )
    )

    return litestar_users_config.user_service_class(
        user_auth_identifier=litestar_users_config.user_auth_identifier,
        user_repository=user_repository,
        role_repository=role_repository,
        secret=litestar_users_config.secret,
        hash_schemes=litestar_users_config.hash_schemes,
        require_verification_on_registration=litestar_users_config.require_verification_on_registration,
    )
