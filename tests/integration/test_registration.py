from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import ANY

import pytest

from litestar_users.main import LitestarUsersPlugin

if TYPE_CHECKING:
    from litestar import Litestar
    from litestar.testing import TestClient


class TestRegistration:
    @pytest.fixture()
    def _disable_require_verification_on_registration(self, app: Litestar) -> None:
        app.plugins.get(LitestarUsersPlugin)._config.require_verification_on_registration = False

    def test_basic_registration(self, client: TestClient) -> None:
        response = client.post(
            "/register", json={"email": "someone@example.com", "username": "generic", "password": "something"}
        )
        assert response.status_code == 201
        assert response.json() == {
            "id": ANY,
            "email": "someone@example.com",
            "username": "generic",
            "is_active": True,
            "is_verified": False,
        }

    @pytest.mark.usefixtures("_disable_require_verification_on_registration")
    def test_basic_registration_without_verification(self, client: TestClient) -> None:
        response = client.post(
            "/register", json={"email": "someone@example.com", "username": "generic", "password": "something"}
        )
        assert response.status_code == 201
        assert response.json() == {
            "id": ANY,
            "email": "someone@example.com",
            "username": "generic",
            "is_active": True,
            "is_verified": True,
        }

    def test_unique_identifier(self, client: TestClient, generic_user: Any) -> None:
        response = client.post(
            "/register", json={"email": "some@one.com", "username": generic_user.username, "password": "copycat"}
        )
        assert response.status_code == 409

    def test_case_insensitive_identifier(self, client: TestClient) -> None:
        response = client.post(
            "/register", json={"email": "illhaus@example.com", "username": "the_ADMIN", "password": "something"}
        )
        assert response.status_code == 409

    def test_unsafe_fields_unset(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                "email": "danger@there.com",
                "username": "king",
                "password": "something",
                "is_active": False,
                "is_verified": True,
            },
        )
        assert response.status_code == 201
        assert response.json() == {
            "id": ANY,
            "email": "danger@there.com",
            "username": "king",
            "is_active": True,
            "is_verified": False,
        }
