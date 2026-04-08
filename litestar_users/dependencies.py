from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig
from litestar.exceptions import ImproperlyConfiguredException

from litestar_users.utils import get_litestar_users_plugin, get_sqlalchemy_plugin

__all__ = ["provide_current_user", "provide_user_service"]


if TYPE_CHECKING:
    from litestar import Request
    from litestar.datastructures import State

    from litestar_users.service import BaseUserService


def provide_current_user(request: Request) -> Any:
    """Expose ``request.user`` as a named dependency.

    Register this at the app level::

        Provide(provide_current_user, sync_to_thread=False)

    Then declare the desired user type on each handler::

        async def handler(current_user: MyUser) -> ...:  # auth required
        async def handler(
            current_user: Annotated[MyUser | AnonymousUser, no_validation],
        ) -> ...:  # anonymous OK
    """
    return request.user


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
        auto_commit=litestar_users_config.auto_commit_transactions,
    )
    role_repo_class = (
        litestar_users_config.role_management_handler_config.role_repository_class
        if litestar_users_config.role_management_handler_config
        else None
    )
    role_repository = (
        None
        if role_repo_class is None
        else role_repo_class(
            session=session,
            auto_commit=litestar_users_config.auto_commit_transactions,
        )
    )
    oauth2_repository = (
        None
        if litestar_users_config.oauth_account_repository_class is None
        else litestar_users_config.oauth_account_repository_class(
            session=session,
            auto_commit=litestar_users_config.auto_commit_transactions,
        )
    )

    return litestar_users_config.user_service_class(
        user_auth_identifier=litestar_users_config.user_auth_identifier,
        user_repository=user_repository,
        role_repository=role_repository,
        oauth2_repository=oauth2_repository,
        secret=litestar_users_config.secret,
        hash_schemes=litestar_users_config.hash_schemes,
        require_verification_on_registration=litestar_users_config.require_verification_on_registration,
    )
