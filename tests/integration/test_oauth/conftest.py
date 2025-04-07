import asyncio
from collections.abc import AsyncIterator, Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDBase
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from httpx_oauth.oauth2 import OAuth2
from litestar.dto import DataclassDTO
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.security.jwt import JWTAuth, JWTCookieAuth
from litestar.security.session_auth import SessionAuth
from pytest_mock import MockerFixture
from sqlalchemy import ForeignKey, Text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_users import LitestarUsersConfig
from litestar_users.adapter.sqlalchemy.mixins import (
    SQLAlchemyOAuthAccountMixin,
    SQLAlchemyUserMixin,
)
from litestar_users.config import CurrentUserHandlerConfig, OAuth2HandlerConfig
from litestar_users.service import BaseUserService
from tests.conftest import password_manager
from tests.constants import ENCODING_SECRET
from tests.utils import MockAuth

if TYPE_CHECKING:
    from litestar.testing import TestClient


@pytest.fixture(scope="session")
def models() -> Generator[dict[str, Any], None, None]:
    UUIDBase.metadata.clear()

    class OAuthAccount(UUIDBase, SQLAlchemyOAuthAccountMixin):
        user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))  # type: ignore[assignment]

    class User(UUIDBase, SQLAlchemyUserMixin):
        # data columns
        # username is only added here because of a rubbish race condition where all `conftest.py` modules are loaded
        # on test suite init, thus messing with the UUIDBase metadata. `username` is required in the integration suite.
        username: Mapped[str] = mapped_column(Text(), unique=True)
        # relationships
        oauth_accounts: Mapped[list[OAuthAccount]] = relationship(OAuthAccount, lazy="selectin")

    @dataclass
    class UserRegistrationSchema:
        email: str
        username: str
        password: str

    class UserRegistrationDTO(DataclassDTO[UserRegistrationSchema]):
        """User registration DTO."""

    class UserReadDTO(SQLAlchemyDTO[User]):
        config = SQLAlchemyDTOConfig(exclude={"password", "password_hash", "oauth_accounts"})

    class UserUpdateDTO(SQLAlchemyDTO[User]):
        """User update DTO."""

        config = SQLAlchemyDTOConfig(exclude={"id", "password", "password_hash", "oauth_accounts"}, partial=True)

    _models = {
        "OAuthAccount": OAuthAccount,
        "User": User,
        "UserRegistrationSchema": UserRegistrationSchema,
        "UserRegistrationDTO": UserRegistrationDTO,
        "UserReadDTO": UserReadDTO,
        "UserUpdateDTO": UserUpdateDTO,
    }
    yield _models
    UUIDBase.metadata.clear()


class UserService(BaseUserService[Any, Any, Any]):
    pass


@pytest.fixture
def user_service() -> type[UserService]:
    return UserService


@pytest.fixture()
def generic_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("3294ab42-3ef0-4bd8-844d-842ba421e46e"),
        email="test1@example.com",
        username="test1",
        password_hash=password_manager.hash("justauser"),
        is_active=True,
        is_verified=True,
    )


@pytest.fixture()
def inactive_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("fc7ed851-d7c6-412d-9f79-4780b80e4fb0"),
        email="test2@example.com",
        username="test2",
        password_hash=password_manager.hash("justauser"),
        is_active=False,
    )


@pytest.fixture()
def verified_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("c382c9ec-e7be-43cd-80cc-f421e5308d76"),
        email="test3@example.com",
        username="test3",
        password_hash=password_manager.hash("justauser"),
        is_active=True,
        is_verified=True,
    )


@pytest.fixture
def oauth_account1(generic_user: Any, models: dict[str, Any]) -> Any:
    return models["OAuthAccount"](
        user_id=generic_user.id,
        oauth_name="service1",
        access_token="TOKEN",
        expires_at=1579000751,
        account_id="user_oauth1",
        account_email="test1@example.com",
    )


@pytest.fixture
def oauth_account2(generic_user: Any, models: dict[str, Any]) -> Any:
    return models["OAuthAccount"](
        user_id=generic_user.id,
        oauth_name="service2",
        access_token="TOKEN",
        expires_at=1579000751,
        account_id="user_oauth2",
        account_email="test1@example.com",
    )


@pytest.fixture
def oauth_account3(inactive_user: Any, models: dict[str, Any]) -> Any:
    return models["OAuthAccount"](
        user_id=inactive_user.id,
        oauth_name="service1",
        access_token="TOKEN",
        expires_at=1579000751,
        account_id="inactive_user_oauth1",
        account_email="test2@example.com",
    )


@pytest.fixture
def oauth_account4(verified_user: Any, models: dict[str, Any]) -> Any:
    return models["OAuthAccount"](
        user_id=verified_user.id,
        oauth_name="service1",
        access_token="TOKEN",
        expires_at=1579000751,
        account_id="verified_user_oauth1",
        account_email="test3@example.com",
    )


@pytest.fixture
def oauth_client() -> OAuth2:
    CLIENT_ID = "CLIENT_ID"
    CLIENT_SECRET = "CLIENT_SECRET"
    AUTHORIZE_ENDPOINT = "https://testdomain.com/authorize"
    ACCESS_TOKEN_ENDPOINT = "https://testdomain.com/access-token"

    return OAuth2(
        CLIENT_ID,
        CLIENT_SECRET,
        AUTHORIZE_ENDPOINT,
        ACCESS_TOKEN_ENDPOINT,
        name="service1",
    )


@pytest.fixture(
    params=[
        pytest.param(SessionAuth, id="session"),
        pytest.param(JWTAuth, id="jwt"),
        pytest.param(JWTCookieAuth, id="jwt_cookie"),
    ],
)
def litestar_users_config(
    request: pytest.FixtureRequest, oauth_client: OAuth2, user_service: UserService, models: dict[str, Any]
) -> LitestarUsersConfig:
    return LitestarUsersConfig(  # pyright: ignore
        auth_backend_class=request.param,
        session_backend_config=ServerSideSessionConfig(),
        secret=ENCODING_SECRET,
        user_model=models["User"],  # pyright: ignore
        user_read_dto=models["UserReadDTO"],
        user_registration_dto=models["UserRegistrationDTO"],
        user_update_dto=models["UserUpdateDTO"],
        user_service_class=user_service,  # type: ignore[arg-type]
        oauth_account_model=models["OAuthAccount"],  # pyright: ignore
        current_user_handler_config=CurrentUserHandlerConfig(),
        oauth2_handler_config=[
            OAuth2HandlerConfig(
                oauth_client=oauth_client,
                state_secret=ENCODING_SECRET,
                is_verified_by_default=True,
                associate_by_email=True,
                redirect_url="https://testdomain.com/callback_redirect",
            )
        ],
        oauth2_associate_handler_config=[
            OAuth2HandlerConfig(
                oauth_client=oauth_client,
                state_secret=ENCODING_SECRET,
                redirect_url="https://testdomain.com/associate_callback_redirect",
            )
        ],
    )


@pytest.fixture()
def mock_auth(client: "TestClient", litestar_users_config: LitestarUsersConfig) -> MockAuth:
    return MockAuth(client=client, config=litestar_users_config)


AsyncMethodMocker = Callable[..., tuple[MagicMock, Callable[[], None]]]


@pytest.fixture
def async_method_mocker(mocker: MockerFixture) -> AsyncMethodMocker:
    original_methods: dict[str, tuple[Any, Callable[[], Any]]] = {}

    def _async_method_mocker(
        object: Any,
        method: str,
        return_value: Any = None,
    ) -> tuple[MagicMock, Callable[[], None]]:
        def reset_mock() -> None:
            for method, (object, original_method) in original_methods.items():
                setattr(object, method, original_method)

        mock: MagicMock = mocker.MagicMock()

        future: asyncio.Future = asyncio.Future()
        future.set_result(return_value)
        mock.return_value = future
        mock.side_effect = None
        original_methods[method] = (object, getattr(object, method))

        setattr(object, method, mock)

        return mock, reset_mock

    return _async_method_mocker


@pytest.fixture(autouse=True)
async def _seed_db(
    engine: AsyncEngine,
    sessionmaker: async_sessionmaker[AsyncSession],
    generic_user: Any,
    inactive_user: Any,
    verified_user: Any,
    oauth_account1: Any,
    oauth_account2: Any,
    oauth_account3: Any,
    oauth_account4: Any,
    models: dict[str, Any],
) -> "AsyncIterator[None]":
    """Populate test database with.

    Args:
        engine: The SQLAlchemy engine instance.
        sessionmaker: The SQLAlchemy sessionmaker factory.
        raw_users: Test users to add to the database
    """

    metadata = models["User"].metadata
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

    async with sessionmaker() as session:
        session.add_all(
            [generic_user, inactive_user, verified_user, oauth_account1, oauth_account2, oauth_account3, oauth_account4]
        )
        await session.commit()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
