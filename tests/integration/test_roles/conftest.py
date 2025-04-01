from collections.abc import AsyncIterator, Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDBase
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from litestar.dto import DataclassDTO
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.security.jwt import JWTAuth, JWTCookieAuth
from litestar.security.session_auth import SessionAuth
from sqlalchemy import ForeignKey, Text, Uuid
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_users import LitestarUsersConfig
from litestar_users.adapter.sqlalchemy.mixins import (
    SQLAlchemyRoleMixin,
    SQLAlchemyUserMixin,
)
from litestar_users.config import RoleManagementHandlerConfig
from litestar_users.guards import roles_accepted, roles_required
from litestar_users.service import BaseUserService
from tests.conftest import password_manager
from tests.constants import ENCODING_SECRET
from tests.utils import MockAuth

if TYPE_CHECKING:
    from litestar.testing import TestClient


@pytest.fixture(scope="session")
def models() -> Generator[dict[str, Any], None, None]:
    UUIDBase.metadata.clear()

    class Role(UUIDBase, SQLAlchemyRoleMixin):
        pass

    class User(UUIDBase, SQLAlchemyUserMixin):
        # data columns
        # username is only added here because of a rubbish race condition where all `conftest.py` modules are loaded
        # on test suite init, thus messing with the UUIDBase metadata. `username` is required in the integration suite.
        username: Mapped[str] = mapped_column(Text(), unique=True)
        # relationships
        roles: Mapped[list[Role]] = relationship(Role, secondary="user_role", lazy="selectin")

    class UserRole(UUIDBase):
        user_id = mapped_column(Uuid(), ForeignKey("user.id"))
        role_id = mapped_column(Uuid(), ForeignKey("role.id"))

    class RoleReadDTO(SQLAlchemyDTO[Role]):
        """Role read DTO."""

    class RoleCreateDTO(SQLAlchemyDTO[Role]):
        """Role creation DTO."""

        config = SQLAlchemyDTOConfig(exclude={"id"})

    class RoleUpdateDTO(SQLAlchemyDTO[Role]):
        """Role update DTO."""

        config = SQLAlchemyDTOConfig(exclude={"id"}, partial=True)

    @dataclass
    class UserRegistrationSchema:
        email: str
        username: str
        password: str

    class UserRegistrationDTO(DataclassDTO[UserRegistrationSchema]):
        """User registration DTO."""

    class UserReadDTO(SQLAlchemyDTO[User]):
        config = SQLAlchemyDTOConfig(exclude={"password", "password_hash"})

    class UserUpdateDTO(SQLAlchemyDTO[User]):
        """User update DTO."""

        config = SQLAlchemyDTOConfig(exclude={"id", "password", "password_hash", "roles"}, partial=True)

    _models = {
        "Role": Role,
        "User": User,
        "UserRole": UserRole,
        "RoleReadDTO": RoleReadDTO,
        "RoleCreateDTO": RoleCreateDTO,
        "RoleUpdateDTO": RoleUpdateDTO,
        "UserRegistrationSchema": UserRegistrationSchema,
        "UserRegistrationDTO": UserRegistrationDTO,
        "UserReadDTO": UserReadDTO,
        "UserUpdateDTO": UserUpdateDTO,
    }
    yield _models
    UUIDBase.metadata.clear()


class UserService(BaseUserService[Any, Any, Any]):
    pass


@pytest.fixture()
def admin_role(models: dict[str, Any]) -> Any:
    return models["Role"](
        id=UUID("9b62b52c-4278-4124-aca8-783ab281c196"),
        name="administrator",
        description="X",
    )


@pytest.fixture()
def writer_role(models: dict[str, Any]) -> Any:
    return models["Role"](
        id=UUID("76ddde3c-91d0-4b58-baa4-bfc4b3892ab2"),
        name="writer",
        description="He who writes",
    )


@pytest.fixture()
def admin_user(admin_role: Any, models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("01676112-d644-4f93-ab32-562850e89549"),
        email="admin@example.com",
        password_hash=password_manager.hash("iamsuperadmin"),
        username="boss",
        is_active=True,
        is_verified=True,
        roles=[admin_role],
    )


@pytest.fixture()
def generic_user(models: dict[str, Any]) -> Any:
    return models["User"](
        id=UUID("555d9ddb-7033-4819-a983-e817237b88e5"),
        email="good@example.com",
        password_hash=password_manager.hash("justauser"),
        username="x86",
        is_active=True,
        is_verified=True,
        roles=[],
    )


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
        session_backend_config=ServerSideSessionConfig(),
        secret=ENCODING_SECRET,
        user_model=models["User"],  # pyright: ignore
        user_read_dto=models["UserReadDTO"],
        user_registration_dto=models["UserRegistrationDTO"],
        user_update_dto=models["UserUpdateDTO"],
        role_model=models["Role"],  # pyright: ignore
        role_create_dto=models["RoleCreateDTO"],
        role_read_dto=models["RoleReadDTO"],
        role_update_dto=models["RoleUpdateDTO"],
        user_service_class=UserService,
        role_management_handler_config=RoleManagementHandlerConfig(
            guards=[roles_accepted("administrator"), roles_required("administrator")]
        ),
    )


@pytest.fixture()
def mock_auth(client: "TestClient", litestar_users_config: LitestarUsersConfig) -> MockAuth:
    return MockAuth(client=client, config=litestar_users_config)


@pytest.fixture()
def authenticate_admin(mock_auth: MockAuth, admin_user: Any) -> "Generator":
    mock_auth.authenticate(admin_user.id)
    yield


@pytest.fixture()
def authenticate_generic(mock_auth: MockAuth, generic_user: Any) -> "Generator":
    mock_auth.authenticate(generic_user.id)
    yield


@pytest.fixture(autouse=True)
async def _seed_db(
    engine: AsyncEngine,
    sessionmaker: async_sessionmaker[AsyncSession],
    admin_user: Any,
    generic_user: Any,
    admin_role: Any,
    writer_role: Any,
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
        session.add_all([admin_user, generic_user, admin_role, writer_role])
        await session.commit()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
