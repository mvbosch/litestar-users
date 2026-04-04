from __future__ import annotations

from collections.abc import AsyncIterator, Generator, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypedDict
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDBase
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from litestar import Litestar, Request
from litestar.dto import DataclassDTO
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.repository.exceptions import RepositoryError
from litestar.testing import TestClient
from sqlalchemy import Text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import ColumnElement

from litestar_users import JWTAuthConfig, LitestarUsersConfig, LitestarUsersPlugin
from litestar_users.config import AuthHandlerConfig, RegisterHandlerConfig
from litestar_users.exceptions import TokenException, exception_to_http_response
from litestar_users.mixins import SQLAlchemyUserMixin
from litestar_users.password import PasswordManager
from litestar_users.service import BaseUserService
from tests.constants import ENCODING_SECRET, HASH_SCHEMES

if TYPE_CHECKING:
    from collections.abc import Sequence

password_manager = PasswordManager(hash_schemes=HASH_SCHEMES)


class TestMultitenantModels(TypedDict):
    User: type[UUIDBase]
    UserRegistration: type[Any]
    CustomAuthenticationSchema: type[Any]
    UserRegistrationDTO: type[DataclassDTO[Any]]
    UserReadDTO: type[SQLAlchemyDTO[Any]]
    UserUpdateDTO: type[SQLAlchemyDTO[Any]]


@pytest.fixture(scope="session")
def models() -> Generator[TestMultitenantModels, None, None]:
    UUIDBase.metadata.clear()

    class User(UUIDBase, SQLAlchemyUserMixin):
        # No unique constraint on username: multiple tenants may share the
        username: Mapped[str] = mapped_column(Text())
        company_id: Mapped[str | None] = mapped_column(Text(), nullable=True)

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

    _models: TestMultitenantModels = {
        "User": User,
        "UserRegistration": UserRegistration,
        "CustomAuthenticationSchema": CustomAuthenticationSchema,
        "UserRegistrationDTO": UserRegistrationDTO,
        "UserReadDTO": UserReadDTO,
        "UserUpdateDTO": UserUpdateDTO,
    }
    yield _models
    UUIDBase.metadata.clear()


class MultitenantUserService(BaseUserService[Any, Any, Any]):
    """Restricts the authentication query to the tenant in the ``x-company-id`` header."""

    def get_additional_auth_filters(self, data: Any, request: Request | None = None) -> "Sequence[ColumnElement[bool]]":
        company_id = request.headers.get("x-company-id", "") if request else ""
        return [self.user_model.company_id == company_id]


@pytest.fixture()
def admin_user(models: TestMultitenantModels) -> Any:
    return models["User"](
        id=UUID("01676112-d644-4f93-ab32-562850e89549"),
        username="the_admin",
        email="admin@example.com",
        password_hash=password_manager.hash("iamsuperadmin"),
        is_active=True,
        is_verified=True,
    )


@pytest.fixture()
def generic_user(models: TestMultitenantModels) -> Any:
    return models["User"](
        id=UUID("555d9ddb-7033-4819-a983-e817237b88e5"),
        email="good@example.com",
        username="just_me",
        password_hash=password_manager.hash("justauser"),
        is_active=True,
        is_verified=True,
    )


@pytest.fixture()
def user_company_a(models: TestMultitenantModels) -> Any:
    return models["User"](
        id=UUID("d4f85862-79ac-4531-be10-85f6c65c5d79"),
        username="shared_user",
        email="user@company-a.com",
        password_hash=password_manager.hash("secret"),
        is_active=True,
        is_verified=True,
        company_id="company-a",
    )


@pytest.fixture()
def user_company_b(models: TestMultitenantModels) -> Any:
    return models["User"](
        id=UUID("80a58d13-9d17-48d4-9ae3-27d799eb03c9"),
        username="shared_user",
        email="user@company-b.com",
        password_hash=password_manager.hash("secret"),
        is_active=True,
        is_verified=True,
        company_id="company-b",
    )


@pytest.fixture(autouse=True)
async def _seed_db(
    engine: AsyncEngine,
    sessionmaker: async_sessionmaker[AsyncSession],
    admin_user: Any,
    generic_user: Any,
    user_company_a: Any,
    user_company_b: Any,
    models: TestMultitenantModels,
) -> AsyncIterator[None]:
    metadata = models["User"].metadata
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    async with sessionmaker() as session:
        session.add_all([admin_user, generic_user, user_company_a, user_company_b])
        await session.commit()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)


@pytest.fixture()
def multitenant_litestar_users_config(models: TestMultitenantModels) -> LitestarUsersConfig:
    return LitestarUsersConfig(  # pyright: ignore
        auth_config=JWTAuthConfig(),
        authentication_request_schema=models["CustomAuthenticationSchema"],
        user_auth_identifier="username",
        secret=ENCODING_SECRET,
        user_model=models["User"],  # pyright: ignore
        user_read_dto=models["UserReadDTO"],
        user_update_dto=models["UserUpdateDTO"],
        user_registration_dto=models["UserRegistrationDTO"],
        user_service_class=MultitenantUserService,
        require_verification_on_registration=False,
        auth_handler_config=AuthHandlerConfig(),
        register_handler_config=RegisterHandlerConfig(),
    )


@pytest.fixture()
def multitenant_app(
    multitenant_litestar_users_config: LitestarUsersConfig,
    sqlalchemy_plugin: Any,
) -> Litestar:
    return Litestar(
        debug=True,
        exception_handlers={
            RepositoryError: exception_to_http_response,
            TokenException: exception_to_http_response,
        },
        plugins=[sqlalchemy_plugin, LitestarUsersPlugin(config=multitenant_litestar_users_config)],
        route_handlers=[],
    )


@pytest.fixture()
def multitenant_client(multitenant_app: Litestar) -> Iterator[TestClient]:
    with TestClient(app=multitenant_app, session_config=ServerSideSessionConfig()) as client:
        yield client
