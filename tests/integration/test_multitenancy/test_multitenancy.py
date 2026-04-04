from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar.testing import TestClient


def test_multitenant_login_correct_company(multitenant_client: TestClient) -> None:
    """Supplying the correct tenant header resolves the right user and succeeds."""
    response = multitenant_client.post(
        "/login",
        json={"username": "shared_user", "password": "secret"},
        headers={"x-company-id": "company-a"},
    )
    assert response.status_code == 201


def test_multitenant_login_wrong_company(multitenant_client: TestClient) -> None:
    """Valid credentials paired with a mismatched tenant header are rejected."""
    response = multitenant_client.post(
        "/login",
        json={"username": "shared_user", "password": "secret"},
        headers={"x-company-id": "wrong-company"},
    )
    assert response.status_code == 401


def test_multitenant_login_missing_company_header(multitenant_client: TestClient) -> None:
    """A login attempt without any tenant header fails even with otherwise valid credentials."""
    response = multitenant_client.post(
        "/login",
        json={"username": "shared_user", "password": "secret"},
    )
    assert response.status_code == 401
