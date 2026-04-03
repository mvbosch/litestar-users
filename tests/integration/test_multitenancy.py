"""Integration tests for get_additional_auth_filters

Two users share the same ``username`` but belong to different tenants, each
identified by the ``x-company-id`` request header.  The custom service
overrides ``get_additional_auth_filters`` to append a ``company_id`` predicate
so that authentication resolves exactly one row regardless of how many tenants
share the same identifier value.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any
from uuid import UUID

import pytest
from litestar import Litestar, Request
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.repository.exceptions import RepositoryError
from litestar.testing import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql import ColumnElement

from litestar_users import JWTAuthConfig, LitestarUsersConfig, LitestarUsersPlugin
from litestar_users.config import AuthHandlerConfig, RegisterHandlerConfig
from litestar_users.exceptions import TokenException, exception_to_http_response
from litestar_users.password import PasswordManager
from litestar_users.service import BaseUserService
from tests.constants import ENCODING_SECRET, HASH_SCHEMES
from tests.integration.conftest import TestModels

password_manager = PasswordManager(hash_schemes=HASH_SCHEMES)


class MultitenantUserService(BaseUserService[Any, Any, Any]):
    """Restricts the authentication query to the tenant in the ``x-company-id`` header."""

    def get_additional_auth_filters(self, data: Any, request: Request | None = None) -> Sequence[ColumnElement[bool]]:
        company_id = request.headers.get("x-company-id", "") if request else ""
        return [self.user_model.company_id == company_id]


@pytest.fixture()
def user_company_a(models: TestModels) -> Any:
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
def user_company_b(models: TestModels) -> Any:
    return models["User"](
        id=UUID("80a58d13-9d17-48d4-9ae3-27d799eb03c9"),
        username="shared_user",
        email="user@company-b.com",
        password_hash=password_manager.hash("secret"),
        is_active=True,
        is_verified=True,
        company_id="company-b",
    )


@pytest.fixture()
async def _seed_multitenant_users(
    sessionmaker: async_sessionmaker[AsyncSession],
    user_company_a: Any,
    user_company_b: Any,
    _seed_db: None,  # ensures the table exists before we insert
) -> AsyncIterator[None]:
    async with sessionmaker() as session:
        session.add_all([user_company_a, user_company_b])
        await session.commit()
    yield


@pytest.fixture()
def multitenant_litestar_users_config(models: TestModels) -> LitestarUsersConfig:
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


@pytest.mark.usefixtures("_seed_multitenant_users")
def test_multitenant_login_correct_company(multitenant_client: TestClient) -> None:
    """Supplying the correct tenant header resolves the right user and succeeds."""
    response = multitenant_client.post(
        "/login",
        json={"username": "shared_user", "password": "secret"},
        headers={"x-company-id": "company-a"},
    )
    assert response.status_code == 201


@pytest.mark.usefixtures("_seed_multitenant_users")
def test_multitenant_login_wrong_company(multitenant_client: TestClient) -> None:
    """Valid credentials paired with a mismatched tenant header are rejected."""
    response = multitenant_client.post(
        "/login",
        json={"username": "shared_user", "password": "secret"},
        headers={"x-company-id": "wrong-company"},
    )
    assert response.status_code == 401


@pytest.mark.usefixtures("_seed_multitenant_users")
def test_multitenant_login_missing_company_header(multitenant_client: TestClient) -> None:
    """A login attempt without any tenant header fails even with otherwise valid credentials."""
    response = multitenant_client.post(
        "/login",
        json={"username": "shared_user", "password": "secret"},
    )
    assert response.status_code == 401
