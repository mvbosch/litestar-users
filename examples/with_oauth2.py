from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import uvicorn
from advanced_alchemy.base import UUIDBase
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig, SQLAlchemyInitPlugin
from httpx_oauth.clients.google import GoogleOAuth2
from litestar import Litestar, Request
from litestar.dto import DataclassDTO
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.security.session_auth import SessionAuth
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_users import LitestarUsersConfig, LitestarUsersPlugin
from litestar_users.adapter.sqlalchemy.mixins import SQLAlchemyOAuthAccountMixin, SQLAlchemyUserMixin
from litestar_users.config import (
    AuthHandlerConfig,
    CurrentUserHandlerConfig,
    OAuth2HandlerConfig,
    PasswordResetHandlerConfig,
    RegisterHandlerConfig,
    RoleManagementHandlerConfig,
    UserManagementHandlerConfig,
    VerificationHandlerConfig,
)
from litestar_users.guards import roles_accepted, roles_required
from litestar_users.password import PasswordManager
from litestar_users.service import BaseUserService

ENCODING_SECRET = "1234567890abcdef"  # noqa: S105
DATABASE_URL = "sqlite+aiosqlite:///"
password_manager = PasswordManager()
UUIDBase.metadata.clear()


class OAuthAccount(UUIDBase, SQLAlchemyOAuthAccountMixin):
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))


class User(UUIDBase, SQLAlchemyUserMixin):
    title: Mapped[str] = mapped_column(String(20))
    login_count: Mapped[int] = mapped_column(Integer(), default=0)

    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(OAuthAccount, lazy="selectin")


@dataclass
class UserRegistrationSchema:
    email: str
    password: str
    title: str


class UserRegistrationDTO(DataclassDTO[UserRegistrationSchema]):
    """User registration DTO."""


class UserReadDTO(SQLAlchemyDTO[User]):
    config = SQLAlchemyDTOConfig(exclude={"password_hash"})


class UserUpdateDTO(SQLAlchemyDTO[User]):
    # we'll update `login_count` in UserService.post_login_hook
    config = SQLAlchemyDTOConfig(exclude={"id", "login_count"}, partial=True)
    # we'll update `login_count` in the UserService.post_login_hook


class UserService(BaseUserService[User, Any, OAuthAccount]):  # type: ignore[type-var]
    async def post_login_hook(self, user: User, request: Request | None = None) -> None:
        # This will properly increment the user's `login_count`
        user.login_count += 1  # pyright: ignore


sqlalchemy_config = SQLAlchemyAsyncConfig(
    connection_string=DATABASE_URL,
    session_dependency_key="session",
)


# See https://frankie567.github.io/httpx-oauth/ for more details
oauth_client = GoogleOAuth2("CLIENT_ID", "CLIENT_SECRET", name="google")


async def on_startup() -> None:
    """Initialize the database."""
    async with sqlalchemy_config.get_engine().begin() as conn:  # pyright: ignore
        await conn.run_sync(UUIDBase.metadata.create_all)


litestar_users_plugin = LitestarUsersPlugin(
    config=LitestarUsersConfig(
        auth_backend_class=SessionAuth,
        session_backend_config=ServerSideSessionConfig(),
        secret=ENCODING_SECRET,
        user_model=User,  # pyright: ignore
        user_read_dto=UserReadDTO,
        user_registration_dto=UserRegistrationDTO,
        user_update_dto=UserUpdateDTO,
        user_service_class=UserService,  # pyright: ignore
        auth_handler_config=AuthHandlerConfig(),
        current_user_handler_config=CurrentUserHandlerConfig(),
        password_reset_handler_config=PasswordResetHandlerConfig(),
        register_handler_config=RegisterHandlerConfig(),
        role_management_handler_config=RoleManagementHandlerConfig(guards=[roles_accepted("administrator")]),
        user_management_handler_config=UserManagementHandlerConfig(guards=[roles_required("administrator")]),
        verification_handler_config=VerificationHandlerConfig(),
        oauth_account_model=OAuthAccount,  # pyright: ignore
        oauth2_handler_config=[
            OAuth2HandlerConfig(
                oauth_client=oauth_client,
                state_secret="state_secret",  # noqa: S106
                is_verified_by_default=True,
            )
        ],
    )
)

app = Litestar(
    debug=True,
    on_startup=[on_startup],
    plugins=[SQLAlchemyInitPlugin(config=sqlalchemy_config), litestar_users_plugin],
    route_handlers=[],
)

if __name__ == "__main__":
    uvicorn.run(app="with_oauth:app", reload=True)
