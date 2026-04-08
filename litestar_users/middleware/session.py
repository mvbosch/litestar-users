from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.exceptions import NotFoundError
from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException
from litestar.middleware._internal.exceptions import ExceptionHandlerMiddleware
from litestar.middleware.authentication import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.types import ASGIApp, Empty, Method, Receive, Scope, Scopes, Send
from sqlalchemy.orm import Load

from litestar_users.anonymous import AnonymousUser, _route_allows_anonymous
from litestar_users.utils import get_litestar_users_plugin, get_sqlalchemy_plugin

__all__ = ["LitestarUsersSessionMiddleware", "LitestarUsersSessionMiddlewareWrapper"]

if TYPE_CHECKING:
    from advanced_alchemy.repository import LoadSpec
    from litestar.connection import ASGIConnection
    from litestar.middleware.session.base import BaseBackendConfig


def _get_load_options(connection: ASGIConnection) -> LoadSpec | None:
    load_options = connection.route_handler.opt.get("user_load_options")
    if load_options is None:
        return None
    if not isinstance(load_options, Sequence):
        raise ValueError("user_load_options must be a sequence")
    if not all(isinstance(opt, Load) for opt in load_options):
        raise ValueError("all load options must be instances of `sqlalchemy.orm.Load`")
    return load_options


async def _get_user_from_session(session_data: dict[str, Any], connection: ASGIConnection) -> Any | None:
    """Resolve session data to a user row using the app's repository."""
    litestar_users_config = get_litestar_users_plugin(connection.app)._config
    sqlalchemy_config = get_sqlalchemy_plugin(connection.app).config[0]
    if not isinstance(sqlalchemy_config, SQLAlchemyAsyncConfig):
        raise ImproperlyConfiguredException("SQLAlchemy config must be of type `SQLAlchemyAsyncConfig`")
    async_session = sqlalchemy_config.provide_session(state=connection.app.state, scope=connection.scope)
    repository = litestar_users_config.user_repository_class(
        session=async_session,
        auto_commit=litestar_users_config.auto_commit_transactions,
    )
    try:
        user_id = session_data.get("user_id")
        if user_id is None:
            return None
        try:
            user_id = UUID(user_id)
        except ValueError:
            user_id = int(user_id)
        user = await repository.get(user_id, load=_get_load_options(connection))
        if user.is_active and user.is_verified:
            return user
    except NotFoundError:
        pass
    return None


class LitestarUsersSessionMiddleware(AbstractAuthenticationMiddleware):
    """Session authentication middleware for litestar-users.

    Performs user lookup against the configured SQLAlchemy repository.

    Missing or empty sessions produce a 401 unless the matched route handler
    declares ``AnonymousUser`` in its ``current_user`` parameter (e.g.
    ``Annotated[MyUser | AnonymousUser, no_validation]``), in which case
    ``request.user`` is set to ``AnonymousUser``. A stale session (user no
    longer found or inactive/unverified) is always cleared; anonymous handling
    follows the same per-route rule.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        exclude: str | list[str] | None,
        exclude_from_auth_key: str,
        exclude_http_methods: Sequence[Method] | None,
        scopes: Scopes | None,
    ) -> None:
        super().__init__(
            app=app,
            exclude=exclude,
            exclude_from_auth_key=exclude_from_auth_key,
            exclude_http_methods=exclude_http_methods,
            scopes=scopes,
        )

    async def authenticate_request(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthenticationResult:
        if not connection.session or connection.scope["session"] is Empty:
            if _route_allows_anonymous(connection):
                return AuthenticationResult(user=AnonymousUser(), auth=None)
            connection.scope["session"] = Empty
            raise NotAuthorizedException("no session data found")

        user = await _get_user_from_session(connection.session, connection)
        if not user:
            connection.scope["session"] = Empty
            if _route_allows_anonymous(connection):
                return AuthenticationResult(user=AnonymousUser(), auth=None)
            raise NotAuthorizedException("no user correlating to session found")

        return AuthenticationResult(user=user, auth=connection.session)


class LitestarUsersSessionMiddlewareWrapper:
    """Wraps ``LitestarUsersSessionMiddleware`` with the session backend and exception handler.

    Used as the target of ``DefineMiddleware`` so that Litestar instantiates the
    full middleware stack lazily on first request.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        session_backend_config: BaseBackendConfig,
        exclude: str | list[str] | None,
        exclude_from_auth_key: str,
        exclude_http_methods: Sequence[Method] | None,
        scopes: Scopes | None,
    ) -> None:
        self.app = app
        self.session_backend_config = session_backend_config
        self.exclude = exclude
        self.exclude_from_auth_key = exclude_from_auth_key
        self.exclude_http_methods = exclude_http_methods
        self.scopes = scopes
        self.has_wrapped_middleware = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.has_wrapped_middleware:
            auth_middleware = LitestarUsersSessionMiddleware(
                app=self.app,
                exclude=self.exclude,
                exclude_from_auth_key=self.exclude_from_auth_key,
                exclude_http_methods=self.exclude_http_methods,
                scopes=self.scopes,
            )
            exception_middleware = ExceptionHandlerMiddleware(app=auth_middleware, debug=None)
            session_backend = self.session_backend_config._backend_class(config=self.session_backend_config)
            self.app = self.session_backend_config.middleware.middleware(
                app=exception_middleware,
                backend=session_backend,
            )
            self.has_wrapped_middleware = True
        await self.app(scope, receive, send)
