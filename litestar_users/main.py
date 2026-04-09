from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.exceptions import RepositoryError
from advanced_alchemy.types import GUID
from litestar.di import Provide
from litestar.dto import DTOData
from litestar.middleware.base import DefineMiddleware
from litestar.middleware.session.base import BaseBackendConfig
from litestar.openapi.spec import Components, SecurityScheme
from litestar.plugins import CLIPluginProtocol, InitPluginProtocol
from sqlalchemy.sql.sqltypes import BigInteger, Uuid

from litestar_users.config import JWTCookieAuthConfig
from litestar_users.dependencies import provide_current_user
from litestar_users.exceptions import TokenException, exception_to_http_response
from litestar_users.middleware import (
    LitestarUsersJWTCookieMiddleware,
    LitestarUsersJWTMiddleware,
    LitestarUsersSessionMiddlewareWrapper,
)
from litestar_users.route_handlers import (
    get_auth_handler,
    get_current_user_handler,
    get_oauth2_associate_handler,
    get_oauth2_handler,
    get_password_reset_handler,
    get_registration_handler,
    get_role_management_handler,
    get_user_management_handler,
    get_verification_handler,
)
from litestar_users.schema import ForgotPasswordSchema, ResetPasswordSchema, UserRoleSchema

__all__ = ["LitestarUsersPlugin"]


if TYPE_CHECKING:
    from collections.abc import Sequence

    from click import Group
    from litestar import Router
    from litestar.config.app import AppConfig
    from litestar.handlers import HTTPRouteHandler

    from litestar_users.config import LitestarUsersConfig


class LitestarUsersPlugin(InitPluginProtocol, CLIPluginProtocol):
    """A Litestar extension for authentication, authorization and user management."""

    def __init__(self, config: LitestarUsersConfig) -> None:
        """Construct a LitestarUsers instance."""
        self._config = config

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Register routers, auth strategies etc on the Litestar app.

        Args:
            app_config: An instance of [AppConfig][litestar.config.AppConfig]
        """
        is_session_auth = isinstance(self._config.auth_config, BaseBackendConfig)

        self._register_middleware(app_config)
        self._register_openapi_security(app_config)

        route_handlers = self._get_route_handlers(is_session_auth)
        app_config.route_handlers.extend(route_handlers)

        app_config.exception_handlers.update({TokenException: exception_to_http_response})

        # don't override user defined advanced-alchemy exception handlers
        if RepositoryError not in app_config.exception_handlers:
            app_config.exception_handlers.update({RepositoryError: exception_to_http_response})

        app_config.signature_namespace.update(
            {
                "ForgotPasswordSchema": ForgotPasswordSchema,
                "ResetPasswordSchema": ResetPasswordSchema,
                "authentication_schema": self._config.authentication_request_schema,
                "UserRoleSchema": UserRoleSchema,
                "UserServiceType": self._config.user_service_class,
                "BaseUserService": self._config.user_service_class,
                "SQLAUserT": self._config.user_repository_class.model_type,  # pyright: ignore[reportGeneralTypeIssues]
                "SQLARoleT": self._config.role_management_handler_config.role_repository_class.model_type  # pyright: ignore[reportGeneralTypeIssues]
                if self._config.role_management_handler_config
                else None,
                "SQLAOAuthAccountT": self._config.oauth_account_repository_class.model_type  # pyright: ignore[reportGeneralTypeIssues]
                if self._config.oauth_account_repository_class
                else None,
                "user_read_dto": self._config.user_read_dto,
                "user_update_dto": self._config.user_update_dto,
                "user_registration_dto": self._config.user_registration_dto,
                "DTOData": DTOData,
                "UserRegisterT": self._config.user_registration_dto.model_type,  # pyright: ignore[reportGeneralTypeIssues]
                "UUID": UUID,
            }
        )
        if self._config.role_management_handler_config:
            app_config.signature_namespace.update(
                {
                    "role_create_dto": self._config.role_management_handler_config.role_create_dto,
                    "role_read_dto": self._config.role_management_handler_config.role_read_dto,
                    "role_update_dto": self._config.role_management_handler_config.role_update_dto,
                }
            )

        app_config.state.update({"litestar_users_config": self._config})

        # Register current_user dependency unless the app already provides one
        if "current_user" not in app_config.dependencies:
            app_config.dependencies["current_user"] = Provide(provide_current_user, sync_to_thread=False)

        return app_config

    def on_cli_init(self, cli: Group) -> None:
        from litestar_users.cli import user_management_group  # noqa: PLC0415

        cli.add_command(user_management_group)

    def _register_middleware(self, app_config: AppConfig) -> None:
        auth_config = self._config.auth_config
        exclude = self._config.auth_exclude_paths
        exclude_opt_key = "exclude_from_auth"
        exclude_http_methods = ["OPTIONS", "HEAD"]

        if isinstance(auth_config, BaseBackendConfig):
            middleware = DefineMiddleware(
                LitestarUsersSessionMiddlewareWrapper,
                session_backend_config=auth_config,
                exclude=exclude,
                exclude_from_auth_key=exclude_opt_key,
                exclude_http_methods=exclude_http_methods,
                scopes=None,
            )
        elif isinstance(auth_config, JWTCookieAuthConfig):
            middleware = DefineMiddleware(
                LitestarUsersJWTCookieMiddleware,
                algorithm=auth_config.algorithm,
                auth_header=auth_config.auth_header,
                cookie_key=auth_config.cookie_key,
                token_secret=self._config.secret,
                exclude=exclude,
                exclude_from_auth_key=exclude_opt_key,
                exclude_http_methods=exclude_http_methods,
                scopes=None,
            )
        else:
            # Plain JWTAuthConfig
            middleware = DefineMiddleware(
                LitestarUsersJWTMiddleware,
                algorithm=auth_config.algorithm,
                auth_header=auth_config.auth_header,
                token_secret=self._config.secret,
                exclude=exclude,
                exclude_from_auth_key=exclude_opt_key,
                exclude_http_methods=exclude_http_methods,
                scopes=None,
            )

        app_config.middleware.insert(0, middleware)

    def _register_openapi_security(self, app_config: AppConfig) -> None:
        """Inject OpenAPI security scheme and requirement based on the auth config."""
        if app_config.openapi_config is None:
            return

        auth_config = self._config.auth_config

        if isinstance(auth_config, BaseBackendConfig):
            scheme_name = "sessionCookie"
            scheme = SecurityScheme(
                type="apiKey",
                name=auth_config.key,
                security_scheme_in="cookie",
                description="Session cookie authentication.",
            )
        elif isinstance(auth_config, JWTCookieAuthConfig):
            scheme_name = "BearerToken"
            scheme = SecurityScheme(
                type="http",
                scheme="Bearer",
                name=auth_config.cookie_key,
                security_scheme_in="cookie",
                bearer_format="JWT",
                description="JWT cookie-based authentication and authorization.",
            )
        else:
            scheme_name = "BearerToken"
            scheme = SecurityScheme(
                type="http",
                scheme="Bearer",
                bearer_format="JWT",
                description="JWT api-key authentication and authorization.",
            )

        components = Components(security_schemes={scheme_name: scheme})
        existing_components = app_config.openapi_config.components
        if isinstance(existing_components, list):
            app_config.openapi_config.components = [*existing_components, components]
        else:
            app_config.openapi_config.components = [components, existing_components]

        security_requirement: dict[str, list[str]] = {scheme_name: []}
        existing_security = app_config.openapi_config.security
        if isinstance(existing_security, list):
            app_config.openapi_config.security = [*existing_security, security_requirement]
        else:
            app_config.openapi_config.security = [security_requirement]

    def _get_user_identifier_uri(self) -> str:
        if isinstance(self._config.user_repository_class.model_type.id.type, (GUID, Uuid)):  # pyright: ignore[reportGeneralTypeIssues]
            return "/{user_id:uuid}"
        if isinstance(self._config.user_repository_class.model_type.id.type, BigInteger):  # pyright: ignore[reportGeneralTypeIssues]
            return "/{user_id:int}"
        raise ValueError("user identifier type not supported")

    def _get_role_identifier_uri(self) -> str:
        role_model = self._config.role_management_handler_config.role_repository_class.model_type  # type: ignore[union-attr]  # pyright: ignore[reportGeneralTypeIssues]
        if isinstance(role_model.id.type, (GUID, Uuid)):
            return "/{role_id:uuid}"
        if isinstance(role_model.id.type, BigInteger):
            return "/{role_id:int}"
        raise ValueError("role identifier type not supported")

    def _get_route_handlers(self, is_session_auth: bool) -> Sequence[HTTPRouteHandler | Router]:
        """Parse the route handler configs to get Routers."""

        handlers: list[HTTPRouteHandler | Router] = []
        if self._config.auth_handler_config:
            handlers.append(
                get_auth_handler(
                    login_path=self._config.auth_handler_config.login_path,
                    logout_path=self._config.auth_handler_config.logout_path,
                    user_read_dto=self._config.auth_handler_config.user_read_dto or self._config.user_read_dto,
                    is_session_auth=is_session_auth,
                    authentication_schema=self._config.authentication_request_schema,
                    tags=self._config.auth_handler_config.tags,
                    opt=self._config.auth_handler_config.opt,
                )
            )
        if self._config.current_user_handler_config:
            handlers.append(
                get_current_user_handler(
                    opt=self._config.current_user_handler_config.opt,
                    path=self._config.current_user_handler_config.path,
                    user_read_dto=self._config.current_user_handler_config.user_read_dto or self._config.user_read_dto,
                    user_update_dto=self._config.user_update_dto,
                    tags=self._config.current_user_handler_config.tags,
                )
            )
        if self._config.password_reset_handler_config:
            handlers.append(
                get_password_reset_handler(
                    forgot_path=self._config.password_reset_handler_config.forgot_path,
                    reset_path=self._config.password_reset_handler_config.reset_path,
                    tags=self._config.password_reset_handler_config.tags,
                )
            )
        if self._config.register_handler_config:
            handlers.append(
                get_registration_handler(
                    path=self._config.register_handler_config.path,
                    user_registration_dto=self._config.user_registration_dto,
                    user_read_dto=self._config.user_read_dto,
                    tags=self._config.register_handler_config.tags,
                )
            )
        if self._config.oauth2_handler_config:
            for config in self._config.oauth2_handler_config:
                handlers.append(
                    get_oauth2_handler(
                        path=config.path,
                        tags=config.tags,
                        guards=config.guards,
                        oauth_client=config.oauth_client,
                        user_read_dto=self._config.user_read_dto,
                        is_session_auth=is_session_auth,
                        state_secret=config.state_secret,
                        redirect_url=config.redirect_url,
                        associate_by_email=config.associate_by_email,
                        is_verified_by_default=config.is_verified_by_default,
                    )
                )
        if self._config.oauth2_associate_handler_config:
            for config in self._config.oauth2_associate_handler_config:
                handlers.append(
                    get_oauth2_associate_handler(
                        path=config.path,
                        tags=config.tags,
                        guards=config.guards,
                        oauth_client=config.oauth_client,
                        user_read_dto=self._config.user_read_dto,
                        is_session_auth=is_session_auth,
                        state_secret=config.state_secret,
                        redirect_url=config.redirect_url,
                        associate_by_email=config.associate_by_email,
                        is_verified_by_default=config.is_verified_by_default,
                    )
                )
        if self._config.role_management_handler_config:
            handlers.append(
                get_role_management_handler(
                    path_prefix=self._config.role_management_handler_config.path_prefix,
                    assign_role_path=self._config.role_management_handler_config.assign_role_path,
                    revoke_role_path=self._config.role_management_handler_config.revoke_role_path,
                    guards=self._config.role_management_handler_config.guards,
                    identifier_uri=self._get_role_identifier_uri(),
                    role_create_dto=self._config.role_management_handler_config.role_create_dto,
                    role_read_dto=self._config.role_management_handler_config.role_read_dto,
                    role_update_dto=self._config.role_management_handler_config.role_update_dto,
                    user_read_dto=self._config.user_read_dto,
                    opt=self._config.role_management_handler_config.opt,
                    tags=self._config.role_management_handler_config.tags,
                )
            )
        if self._config.user_management_handler_config:
            handlers.append(
                get_user_management_handler(
                    path_prefix=self._config.user_management_handler_config.path_prefix,
                    guards=self._config.user_management_handler_config.guards,
                    identifier_uri=self._get_user_identifier_uri(),
                    user_read_dto=self._config.user_management_handler_config.user_read_dto
                    or self._config.user_read_dto,
                    user_update_dto=self._config.user_update_dto,
                    opt=self._config.user_management_handler_config.opt,
                    tags=self._config.user_management_handler_config.tags,
                )
            )
        if self._config.verification_handler_config:
            handlers.append(
                get_verification_handler(
                    path=self._config.verification_handler_config.path,
                    user_read_dto=self._config.user_read_dto,
                    tags=self._config.verification_handler_config.tags,
                )
            )
        return handlers
