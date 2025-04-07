from __future__ import annotations

from typing import Any

from litestar.testing import TestClient


def test_forgot_password(client: TestClient, generic_user: Any) -> None:
    response = client.post("/forgot-password", json={"email": generic_user.email})
    assert response.status_code == 201


def test_reset_password(client: TestClient, generic_user: Any, generic_user_password_reset_token: str) -> None:
    PASSWORD = "veryverystrong123"
    response = client.post(
        "/reset-password",
        json={
            "token": generic_user_password_reset_token,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 201
