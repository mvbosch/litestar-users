from typing import TYPE_CHECKING, Any
from unittest.mock import ANY

import pytest

if TYPE_CHECKING:
    from litestar.testing import TestClient


@pytest.mark.usefixtures("authenticate_admin")
class TestRoleManagement:
    def test_create_role(self, client: "TestClient") -> None:
        response = client.post("/users/roles", json={"name": "editor", "description": "..."})
        assert response.status_code == 201
        assert response.json() == {
            "id": ANY,
            "name": "editor",
            "description": "...",
        }

    def test_update_role(self, client: "TestClient", writer_role: Any) -> None:
        response = client.patch("/users/roles/76ddde3c-91d0-4b58-baa4-bfc4b3892ab2", json={"name": "editor"})
        assert response.status_code == 200
        assert response.json() == {
            "id": str(writer_role.id),
            "name": "editor",
            "description": writer_role.description,
        }

    def test_delete_role(self, client: "TestClient") -> None:
        response = client.delete("/users/roles/76ddde3c-91d0-4b58-baa4-bfc4b3892ab2")
        assert response.status_code == 200

    def test_assign_role(self, client: "TestClient", generic_user: Any, writer_role: Any) -> None:
        response = client.put(
            "/users/roles/assign", json={"user_id": str(generic_user.id), "role_id": str(writer_role.id)}
        )
        assert response.status_code == 200

    def test_revoke_role(self, client: "TestClient", admin_user: Any, admin_role: Any) -> None:
        response = client.put(
            "/users/roles/revoke", json={"user_id": str(admin_user.id), "role_id": str(admin_role.id)}
        )
        assert response.status_code == 200
