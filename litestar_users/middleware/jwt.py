from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.exceptions import NotFoundError
from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException
from litestar.middleware.authentication import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.security.jwt.token import Token
from sqlalchemy.orm import Load

from litestar_users.anonymous import AnonymousUser, _route_allows_anonymous
from litestar_users.utils import get_litestar_users_plugin, get_sqlalchemy_plugin

__all__ = ["LitestarUsersJWTCookieMiddleware", "LitestarUsersJWTMiddleware"]

if TYPE_CHECKING:
    from advanced_alchemy.repository import LoadSpec
    from litestar.connection import ASGIConnection
    from litestar.types import ASGIApp, Method, Scopes


def _get_load_options(connection: ASGIConnection) -> LoadSpec | None:
    load_options = connection.route_handler.opt.get("user_load_options")
    if load_options is None:
        return None
    if not isinstance(load_options, Sequence):
        raise ValueError("user_load_options must be a sequence")
    if not all(isinstance(opt, Load) for opt in load_options):
        raise ValueError("all load options must be instances of `sqlalchemy.orm.Load`")
    return load_options


async def _get_user_from_sub(sub: str, connection: ASGIConnection) -> Any | None:
    """Resolve a JWT ``sub`` claim to a user row, using the app's repository."""
    litestar_users_config = get_litestar_users_plugin(connection.app)._config
    sqlalchemy_config = get_sqlalchemy_plugin(connection.app).config[0]
    if not isinstance(sqlalchemy_config, SQLAlchemyAsyncConfig):
        raise ImproperlyConfiguredException("SQLAlchemy config must be of type `SQLAlchemyAsyncConfig`")
    session = sqlalchemy_config.provide_session(state=connection.app.state, scope=connection.scope)
    repository = litestar_users_config.user_repository_class(
        session=session,
        model_type=litestar_users_config.user_model,
        auto_commit=litestar_users_config.auto_commit_transactions,
    )
    try:
        try:
            user_id: UUID | int = UUID(sub)
        except ValueError:
            user_id = int(sub)
        user = await repository.get(user_id, load=_get_load_options(connection))
        if user.is_active and user.is_verified:
            return user
    except NotFoundError:
        pass
    return None


class LitestarUsersJWTMiddleware(AbstractAuthenticationMiddleware):
    """JWT authentication middleware for litestar-users.

    Performs user lookup against the configured SQLAlchemy repository so no
    ``retrieve_user_handler`` callback is required.

    Missing credentials produce a 401 unless the matched route handler declares
    ``AnonymousUser`` in its ``current_user`` parameter (e.g.
    ``Annotated[MyUser | AnonymousUser, no_validation]``), in which case
    ``request.user`` is set to ``AnonymousUser``. A present-but-invalid token
    always returns 401.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        algorithm: str,
        auth_header: str,
        token_secret: str,
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
        self.algorithm = algorithm
        self.auth_header = auth_header
        self.token_secret = token_secret

    async def authenticate_request(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthenticationResult:
        auth_header = connection.headers.get(self.auth_header)
        if not auth_header:
            if _route_allows_anonymous(connection):
                return AuthenticationResult(user=AnonymousUser(), auth=None)
            raise NotAuthorizedException("No JWT token found in request header")
        encoded_token = auth_header.partition(" ")[-1]
        return await self._authenticate_token(encoded_token, connection)

    async def _authenticate_token(
        self, encoded_token: str, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationResult:
        token = Token.decode(
            encoded_token=encoded_token,
            secret=self.token_secret,
            algorithm=self.algorithm,
        )
        user = await _get_user_from_sub(token.sub, connection)
        if not user:
            raise NotAuthorizedException()
        return AuthenticationResult(user=user, auth=token)


class LitestarUsersJWTCookieMiddleware(LitestarUsersJWTMiddleware):
    """Cookie-based JWT authentication middleware for litestar-users.

    Reads the token from the ``Authorization`` header first, then falls back to
    the configured cookie. Same anonymous/error semantics as
    ``LitestarUsersJWTMiddleware``.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        algorithm: str,
        auth_header: str,
        cookie_key: str,
        token_secret: str,
        exclude: str | list[str] | None,
        exclude_from_auth_key: str,
        exclude_http_methods: Sequence[Method] | None,
        scopes: Scopes | None,
    ) -> None:
        super().__init__(
            app=app,
            algorithm=algorithm,
            auth_header=auth_header,
            token_secret=token_secret,
            exclude=exclude,
            exclude_from_auth_key=exclude_from_auth_key,
            exclude_http_methods=exclude_http_methods,
            scopes=scopes,
        )
        self.cookie_key = cookie_key

    async def authenticate_request(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthenticationResult:
        encoded_token = (
            connection.headers.get(self.auth_header, "").partition(" ")[-1]
            or connection.cookies.get(self.cookie_key, "").split(" ")[-1]
        )
        if not encoded_token:
            if _route_allows_anonymous(connection):
                return AuthenticationResult(user=AnonymousUser(), auth=None)
            raise NotAuthorizedException("No JWT token found in request header or cookies")
        return await self._authenticate_token(encoded_token, connection)
