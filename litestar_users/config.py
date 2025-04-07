from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Generic

from litestar.exceptions import ImproperlyConfiguredException
from litestar.security.session_auth import SessionAuth

from litestar_users.adapter.sqlalchemy.repository import SQLAlchemyUserRepository
from litestar_users.protocols import OAuthAccountT, RoleT, UserT
from litestar_users.schema import AuthenticationSchema

try:
    from httpx_oauth.oauth2 import BaseOAuth2
except ModuleNotFoundError:
    BaseOAuth2 = Any  # type: ignore[assignment,misc]

__all__ = [
    "AuthHandlerConfig",
    "CurrentUserHandlerConfig",
    "LitestarUsersConfig",
    "PasswordResetHandlerConfig",
    "RegisterHandlerConfig",
    "RoleManagementHandlerConfig",
    "UserManagementHandlerConfig",
    "VerificationHandlerConfig",
]

if TYPE_CHECKING:
    from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO
    from litestar.contrib.pydantic import PydanticDTO
    from litestar.dto import DataclassDTO, MsgspecDTO
    from litestar.middleware.session.base import BaseBackendConfig
    from litestar.security.jwt import JWTAuth, JWTCookieAuth
    from litestar.types import Guard

    from litestar_users.service import BaseUserService

USER_CREATE_DTO_EXCLUDED_FIELDS = {"password_hash"}
USER_READ_DTO_EXCLUDED_FIELDS = {"password"}
DEFAULT_USER_AUTH_IDENTIFIER = "email"


@dataclass
class AuthHandlerConfig:
    """Configuration for user authentication route handlers.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.
    """

    login_path: str = "/login"
    """The path for the user authentication/login route."""
    logout_path: str = "/logout"
    """The path for the logout route."""
    opt: dict[str, Any] = field(default_factory=dict)
    """Optional route handler [opts][litestar.controller.Controller.opt] to provide additional context to Guards."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""
    user_read_dto: type[SQLAlchemyDTO] | None = None
    """Optional user read DTO override.

    Defaults to the global `user_read_dto` in `LitestarUsersConfig`.
    """


@dataclass
class CurrentUserHandlerConfig:
    """Configuration for the current-user route handler.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.
    """

    opt: dict[str, Any] = field(default_factory=dict)
    """Optional route handler [opts][litestar.controller.Controller.opt] to provide additional context to Guards."""
    path: str = "/users/me"
    """The path to get or update the currently logged-in user."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""
    user_read_dto: type[SQLAlchemyDTO] | None = None
    """Optional user read DTO override.

    Defaults to the global `user_read_dto` in `LitestarUsersConfig`.
    """


@dataclass
class PasswordResetHandlerConfig:
    """Configuration for the forgot-password and reset-password route handlers.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.
    """

    forgot_path: str = "/forgot-password"
    """The path for the forgot-password route."""
    reset_path: str = "/reset-password"
    """The path for the reset-password route."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""


@dataclass
class RegisterHandlerConfig:
    """Configuration for the user registration route handler.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.
    """

    path: str = "/register"
    """The path for the registration/signup route."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""


@dataclass
class OAuth2HandlerConfig:
    """Configuration for the OAuth2 route handlers.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler oauth2 auth on the app.
    """

    oauth_client: BaseOAuth2  # pyright: ignore[reportInvalidTypeForm]
    """The OAuth2 client to use."""
    state_secret: str
    """Secret used to encode the state JWT."""
    path: str = "/oauth2"
    """The path for the OAuth2 route."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""
    guards: list[Guard] = field(default_factory=list)
    """A list of callable [Guards][litestar.types.Guard] that determines who is authorized to manage roles."""
    redirect_url: str | None = None
    """The URL to redirect to after the OAuth2 flow.

    If not provided, the current URL will be used.
    """
    associate_by_email: bool = False
    """If True, any existing user with the same e-mail address will be associated to this user. Defaults to False."""
    is_verified_by_default: bool = False
    """If True, the user will be verified by default. Defaults to False."""
    user_read_dto: type[SQLAlchemyDTO] | None = None
    """Optional user read DTO override.

    Defaults to the global `user_read_dto` in `LitestarUsersConfig`.
    """


@dataclass
class RoleManagementHandlerConfig:
    """Configuration for the role management route handlers.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.
    """

    path_prefix: str = "/users/roles"
    """The prefix for the router path."""
    assign_role_path: str = "/assign"
    """The path for the role assignment router."""
    revoke_role_path: str = "/revoke"
    """The path for the role revokement router."""
    guards: list[Guard] = field(default_factory=list)
    """A list of callable [Guards][litestar.types.Guard] that determines who is authorized to manage roles."""
    opt: dict[str, Any] = field(default_factory=dict)
    """Optional route handler [opts][litestar.controller.Controller.opt] to provide additional context to Guards."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""


@dataclass
class UserManagementHandlerConfig:
    """Configuration for user management (read, update, delete) route handlers.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.

    Note:
    - These routes make use of Litestar `Guard`s to require authorization. Callers require admin or similar privileges.
    """

    path_prefix: str = "/users"
    """The prefix for the router path.

    By default, the path will be suffixed with `'/{user_id:<type>}'`.
    """
    guards: list[Guard] = field(default_factory=list)
    """A list of callable [Guards][litestar.types.Guard] that determines who is authorized to manage other users."""
    opt: dict[str, Any] = field(default_factory=dict)
    """Optional route handler [opts][litestar.controller.Controller.opt] to provide additional context to Guards."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""
    user_read_dto: type[SQLAlchemyDTO] | None = None
    """Optional user read DTO override.

    Defaults to the global `user_read_dto` in `LitestarUsersConfig`.
    """


@dataclass
class VerificationHandlerConfig:
    """Configuration for the user verification route handler.

    Passing an instance to `LitestarUsersConfig` will automatically take care of handler registration on the app.
    """

    path: str = "/verify"
    """The path for the verification route."""
    tags: list[str] | None = None
    """A list of string tags to append to the schema of the route handler(s)."""


@dataclass
class LitestarUsersConfig(Generic[UserT, RoleT, OAuthAccountT]):
    """Configuration class for LitestarUsers."""

    auth_backend_class: type[JWTAuth | JWTCookieAuth | SessionAuth]
    """The authentication backend to use by Litestar."""
    secret: str
    """Secret string for securely signing tokens."""
    user_model: type[UserT]
    """A subclass of a `User` ORM model."""
    user_service_class: type[BaseUserService]
    """A subclass of [BaseUserService][litestar_users.service.BaseUserService]."""
    user_registration_dto: type[DataclassDTO | MsgspecDTO | PydanticDTO]
    """DTO class user for user registration."""
    user_read_dto: type[SQLAlchemyDTO]
    """A `User` model based SQLAlchemy DTO class."""
    user_update_dto: type[SQLAlchemyDTO]
    """A `User` model based SQLAlchemy DTO class."""
    user_repository_class: type[SQLAlchemyUserRepository] = SQLAlchemyUserRepository
    """The user repository class to use."""
    authentication_request_schema: Any = AuthenticationSchema
    """The schema to use for authentication requests.

    This can be a dataclass, pydantic `BaseModel` or msgspec `Struct`.
    Requires an attribute with the same name as `user_auth_identifier` as well as a `password` attribute.

    Notes:
        - Required if `user_auth_identifier` is set to a non-default value.
    """
    auth_exclude_paths: list[str] = field(default_factory=lambda: ["/schema"])
    """Paths to be excluded from authentication checks."""
    auto_commit_transactions: bool = False
    """Whether to auto_commit transactions. Defaults to `False`."""
    hash_schemes: list[str] = field(default_factory=lambda: ["argon2"])
    """Schemes to use for password encryption.

    Defaults to `["argon2"]`
    """
    session_backend_config: BaseBackendConfig | None = None
    """Optional backend configuration for session based authentication.

    Notes:
        - Required if `auth_backend_class` is `SessionAuth`.
    """
    default_token_expiration: timedelta = field(default_factory=lambda: timedelta(days=1))
    """The default expiration time for authentication tokens."""
    oauth_account_model: type[OAuthAccountT] | None = None
    """A `OAuthAccount` ORM model."""
    role_model: type[RoleT] | None = None
    """A `Role` ORM model.

    Notes:
        - Required if `role_management_handler_config` is set.
    """
    role_create_dto: type[SQLAlchemyDTO] | None = None
    """A `SQLAlchemyDTO` based on a `Role` ORM model.

    Notes:
        - Required if `role_management_handler_config` is set.
    """
    role_read_dto: type[SQLAlchemyDTO] | None = None
    """A `SQLAlchemyDTO` based on a `Role` ORM model.

    Notes:
        - Required if `role_management_handler_config` is set.
    """
    role_update_dto: type[SQLAlchemyDTO] | None = None
    """A `SQLAlchemyDTO` based on a `Role` ORM model.

    Notes:
        - Required if `role_management_handler_config` is set.
    """
    user_auth_identifier: str = DEFAULT_USER_AUTH_IDENTIFIER
    """The identifying attribute to use during user authentication. Defaults to `'email'`.

    Changing this value requires setting `authentication_request_schema` as well, which would allow login via e.g. `username` instead.

    Notes:
        - The attribute must be present on the `User` database model and must have a unique value.
    """
    require_verification_on_registration: bool = True
    """Whether the registration of a new user requires verification. Defaults to `True`."""
    auth_handler_config: AuthHandlerConfig | None = None
    """Optional instance of [AuthHandlerConfig][litestar_users.config.AuthHandlerConfig]. If set, registers the route
    handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    current_user_handler_config: CurrentUserHandlerConfig | None = None
    """Optional current-user route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    password_reset_handler_config: PasswordResetHandlerConfig | None = None
    """Optional password reset route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    register_handler_config: RegisterHandlerConfig | None = None
    """Optional registration/signup route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    oauth2_handler_config: list[OAuth2HandlerConfig] | None = None
    """Optional OAuth2 route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    oauth2_associate_handler_config: list[OAuth2HandlerConfig] | None = None
    """Optional OAuth2 associate route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    role_management_handler_config: RoleManagementHandlerConfig | None = None
    """Optional role management route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    user_management_handler_config: UserManagementHandlerConfig | None = None
    """Optional user management route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """
    verification_handler_config: VerificationHandlerConfig | None = None
    """Optional user verification route handler configuration. If set, registers the route handler(s) on the app.

    Notes:
        - At least one route handler config must be set.
    """

    def __post_init__(self) -> None:
        """Validate the configuration.

        - A session backend must be configured if `auth_backend_class` is `SessionAuth`.
        - At least one route handler must be configured.
        - `role_model`, `role_create_dto`, `role_read_dto` and `role_update_dto` are required fields if
            `role_management_handler_config` is configured.
        """
        if self.auth_backend_class == SessionAuth and not self.session_backend_config:
            raise ImproperlyConfiguredException(
                'session_backend_config must be set when auth_backend is set to "session"'
            )
        handler_configs = [
            "auth_handler_config",
            "current_user_handler_config",
            "password_reset_handler_config",
            "register_handler_config",
            "role_management_handler_config",
            "oauth2_handler_config",
            "oauth2_associate_handler_config",
            "user_management_handler_config",
            "verification_handler_config",
        ]
        if len(self.secret) not in [16, 24, 32]:
            raise ImproperlyConfiguredException("secret must be 16, 24 or 32 characters")
        if all(getattr(self, config) is None for config in handler_configs):
            raise ImproperlyConfiguredException("at least one route handler must be configured")
        if self.role_management_handler_config and self.role_model is None:
            raise ImproperlyConfiguredException("role_model must be set when role_management_handler_config is set")

        for field_ in self.user_read_dto.generate_field_definitions(self.user_read_dto.model_type):  # pyright: ignore
            if field_.name in USER_READ_DTO_EXCLUDED_FIELDS:
                raise ImproperlyConfiguredException(
                    f"user_read_dto fields must exclude {USER_READ_DTO_EXCLUDED_FIELDS}"
                )
        if not self.user_update_dto.config.partial:
            raise ImproperlyConfiguredException("user_update_dto.config must be partial")

        if (
            is_dataclass(self.authentication_request_schema)
            and self.user_auth_identifier not in self.authentication_request_schema.__dataclass_fields__
        ):
            raise ImproperlyConfiguredException(
                f"authentication schema class {self.authentication_request_schema} "
                f"is missing field '{self.user_auth_identifier}'"
            )
        if not is_dataclass(self.authentication_request_schema) and not hasattr(
            self.authentication_request_schema, self.user_auth_identifier
        ):
            raise ImproperlyConfiguredException(
                f"authentication schema class {self.authentication_request_schema} "
                f"is missing field '{self.user_auth_identifier}'"
            )
        # ensure password is mapped correctly
        self.user_update_dto.config.rename_fields.update({"password_hash": "password"})

        for field_ in self.user_registration_dto.generate_field_definitions(self.user_registration_dto.model_type):  # type: ignore[misc]
            if field_.name in USER_CREATE_DTO_EXCLUDED_FIELDS:
                raise ImproperlyConfiguredException(
                    f"user_registration_dto fields must exclude {USER_CREATE_DTO_EXCLUDED_FIELDS}"
                )
