from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Generator, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDBase
from advanced_alchemy.config import AsyncSessionConfig
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyAsyncConfig, SQLAlchemyInitPlugin
from litestar import Litestar
from litestar.datastructures import State
from litestar.dto import DataclassDTO
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.repository.exceptions import RepositoryError
from litestar.security.jwt import JWTAuth, JWTCookieAuth, Token
from litestar.security.session_auth import SessionAuth
from litestar.testing import TestClient
from sqlalchemy import Text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.pool import NullPool

from litestar_users import LitestarUsersConfig, LitestarUsersPlugin
from litestar_users.adapter.sqlalchemy.mixins import SQLAlchemyUserMixin
from litestar_users.config import (
    AuthHandlerConfig,
    CurrentUserHandlerConfig,
    PasswordResetHandlerConfig,
    RegisterHandlerConfig,
    UserManagementHandlerConfig,
    VerificationHandlerConfig,
)
from litestar_users.exceptions import TokenException, exception_to_http_response
from litestar_users.password import PasswordManager
from litestar_users.service import BaseUserService
from tests.constants import ENCODING_SECRET, HASH_SCHEMES
from tests.utils import MockAuth, basic_guard

if TYPE_CHECKING:
    from collections import abc

password_manager = PasswordManager(hash_schemes=HASH_SCHEMES)
here = Path(__file__).parent


@pytest.fixture(scope="session")
def event_loop() -> "abc.Iterator[asyncio.AbstractEventLoop]":
    """Scoped Event loop.

    Need the event loop scoped to the session so that we can use it to check
    containers are ready in session scoped containers fixture.
    """
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest.fixture(scope="session")
def models() -> Generator[dict[str, Any], None, None]:
    UUIDBase.metadata.clear()

    class User(UUIDBase, SQLAlchemyUserMixin):
        username: Mapped[str] = mapped_column(Text(), unique=True)

    @dataclass
    class UserRegistration:
        email: str
        username: str
        password: str

    @dataclass
    class CustomAuthenticationSchema:
        username: str
        password: str

    class UserRegistrationDTO(DataclassDTO[UserRegistration]):
        """User registration DTO."""

    class UserReadDTO(SQLAlchemyDTO[User]):
        """User read DTO."""

        config = SQLAlchemyDTOConfig(exclude={"password_hash"})

    class UserUpdateDTO(SQLAlchemyDTO[User]):
        """User update DTO."""

        config = SQLAlchemyDTOConfig(exclude={"id", "email"}, rename_fields={"password_hash": "password"}, partial=True)

    _models = {
        "User": User,
        "UserRegistration": UserRegistration,
        "CustomAuthenticationSchema": CustomAuthenticationSchema,
        "UserRegistrationDTO": UserRegistrationDTO,
        "UserReadDTO": UserReadDTO,
        "UserUpdateDTO": UserUpdateDTO,
    }
    yield _models
    UUIDBase.metadata.clear()


class UserService(BaseUserService[Any, Any, Any]):
    pass


@pytest.fixture()
def admin_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("01676112-d644-4f93-ab32-562850e89549"),
        username="the_admin",
        email="admin@example.com",
        password_hash=password_manager.hash("iamsuperadmin"),
        is_active=True,
        is_verified=True,
    )


@pytest.fixture()
def generic_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("555d9ddb-7033-4819-a983-e817237b88e5"),
        email="good@example.com",
        username="just_me",
        password_hash=password_manager.hash("justauser"),
        is_active=True,
        is_verified=True,
    )


@pytest.fixture()
def generic_user_password_reset_token(generic_user: Any) -> str:
    token = Token(
        exp=datetime.now() + timedelta(seconds=60 * 60 * 24),
        sub=str(generic_user.id),
        aud="reset_password",
    )
    return token.encode(secret=ENCODING_SECRET, algorithm="HS256")


@pytest.fixture()
def unverified_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("68dec058-b752-42eb-8e55-b94a7b275f99"),
        email="unverified@example.com",
        username="unverified",
        password_hash=password_manager.hash("notveryverified"),
        is_active=True,
        is_verified=False,
    )


@pytest.fixture()
def unverified_user_token(unverified_user: Any) -> str:
    token = Token(
        exp=datetime.now() + timedelta(seconds=60 * 60 * 24),
        sub=str(unverified_user.id),
        aud="verify",
    )
    return token.encode(secret=ENCODING_SECRET, algorithm="HS256")


@pytest.fixture()
def sqlalchemy_plugin_config(docker_ip: str) -> SQLAlchemyAsyncConfig:
    return SQLAlchemyAsyncConfig(
        connection_string=f"postgresql+asyncpg://postgres:super-secret@{docker_ip}:5423/postgres",
        session_dependency_key="session",
        session_config=AsyncSessionConfig(expire_on_commit=False),
    )


@pytest.fixture()
def sqlalchemy_plugin(sqlalchemy_plugin_config: SQLAlchemyAsyncConfig) -> SQLAlchemyInitPlugin:
    return SQLAlchemyInitPlugin(config=sqlalchemy_plugin_config)


@pytest.fixture(
    params=[
        pytest.param(SessionAuth, id="session"),
        pytest.param(JWTAuth, id="jwt"),
        pytest.param(JWTCookieAuth, id="jwt_cookie"),
    ],
)
def litestar_users_config(request: pytest.FixtureRequest, models: dict[str, Any]) -> LitestarUsersConfig:
    return LitestarUsersConfig(  # pyright: ignore
        auth_backend_class=request.param,
        authentication_request_schema=models["CustomAuthenticationSchema"],
        user_auth_identifier="username",
        session_backend_config=ServerSideSessionConfig(),
        secret=ENCODING_SECRET,
        user_model=models["User"],  # pyright: ignore
        user_registration_dto=models["UserRegistrationDTO"],
        user_read_dto=models["UserReadDTO"],
        user_update_dto=models["UserUpdateDTO"],
        user_service_class=UserService,
        require_verification_on_registration=True,
        auth_handler_config=AuthHandlerConfig(),
        current_user_handler_config=CurrentUserHandlerConfig(),
        password_reset_handler_config=PasswordResetHandlerConfig(),
        register_handler_config=RegisterHandlerConfig(),
        user_management_handler_config=UserManagementHandlerConfig(guards=[basic_guard]),
        verification_handler_config=VerificationHandlerConfig(),
    )


@pytest.fixture()
def litestar_users(litestar_users_config: LitestarUsersConfig) -> LitestarUsersPlugin:
    return LitestarUsersPlugin(config=litestar_users_config)


@pytest.fixture()
def app(litestar_users: LitestarUsersPlugin, sqlalchemy_plugin: SQLAlchemyInitPlugin) -> Litestar:
    return Litestar(
        debug=True,
        exception_handlers={
            RepositoryError: exception_to_http_response,
            TokenException: exception_to_http_response,
        },
        plugins=[sqlalchemy_plugin, litestar_users],
        route_handlers=[],
        state=State({"testing": True}),
    )


@pytest.fixture()
def client(app: Litestar) -> "Iterator[TestClient]":
    with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
        yield client


@pytest.fixture()
def mock_auth(client: TestClient, litestar_users_config: LitestarUsersConfig) -> MockAuth:
    return MockAuth(client=client, config=litestar_users_config)


@pytest.fixture()
def authenticate_admin(mock_auth: MockAuth, admin_user: Any) -> Generator:
    mock_auth.authenticate(admin_user.id)
    yield


@pytest.fixture()
def authenticate_generic(mock_auth: MockAuth, generic_user: Any) -> Generator:
    mock_auth.authenticate(generic_user.id)
    yield


@pytest.fixture(scope="session")
def docker_compose_file() -> Path:
    """Load docker compose file.

    Returns:
        Path to the docker-compose file for end-to-end test environment.
    """
    return here / "docker-compose.yml"


@pytest.fixture(name="engine")
async def fx_engine(docker_ip: str, postgres_service: None) -> AsyncEngine:
    """Postgresql instance for end-to-end testing.

    Args:
        docker_ip: IP address for TCP connection to Docker containers.

    Returns:
        Async SQLAlchemy engine instance.
    """
    return create_async_engine(
        URL(
            drivername="postgresql+asyncpg",
            username="postgres",
            password="super-secret",
            host=docker_ip,
            port=5423,
            database="postgres",
            query={},  # type: ignore[arg-type]  # pyright: ignore
        ),
        echo=False,
        poolclass=NullPool,
    )


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def session(sessionmaker: async_sessionmaker[AsyncSession]) -> AsyncSession:
    return sessionmaker()


@pytest.fixture(autouse=True)
async def _seed_db(
    engine: AsyncEngine,
    sessionmaker: async_sessionmaker[AsyncSession],
    admin_user: Any,
    generic_user: Any,
    unverified_user: Any,
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
        session.add_all([admin_user, generic_user, unverified_user])
        await session.commit()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
