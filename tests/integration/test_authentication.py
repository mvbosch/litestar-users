from __future__ import annotations

from typing import Any

from litestar.security.session_auth import SessionAuth
from litestar.testing import TestClient

from litestar_users import LitestarUsersConfig


def test_login(client: TestClient) -> None:
    success_response = client.post("/login", json={"username": "the_admin", "password": "iamsuperadmin"})
    assert success_response.status_code == 201

    fail_response = client.post("/login", json={"username": "the_admin", "password": "ijustguessed"})
    assert fail_response.status_code == 401


def test_case_insensitive_login(client: TestClient) -> None:
    response = client.post("/login", json={"username": "The_Admin", "password": "iamsuperadmin"})
    assert response.status_code == 201


def test_logout(client: TestClient, generic_user: Any, litestar_users_config: LitestarUsersConfig) -> None:
    client.set_session_data({"user_id": str(generic_user.id)})
    response = client.post("/logout")
    if litestar_users_config.auth_backend_class != SessionAuth:
        assert response.status_code == 404
    else:
        assert response.status_code == 201
        assert client.get_session_data().get("user_id") is None
