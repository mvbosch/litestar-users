"""Smoke-tests for the example applications.

Each test class:
- imports the example's ``app`` object to verify it builds without errors
- checks that the expected route paths are registered
- runs a register → login cycle
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest
from litestar.middleware.session.base import BaseBackendConfig
from litestar.testing import TestClient

from litestar_users.main import LitestarUsersPlugin


def _route_paths(app: Any) -> set[str]:
    return {route.path for route in app.routes}


def _make_client(app: Any) -> TestClient:
    plugin = app.plugins.get(LitestarUsersPlugin)
    auth_config = plugin._config.auth_config
    if isinstance(auth_config, BaseBackendConfig):
        return TestClient(app=app, session_config=auth_config)
    return TestClient(app=app)


def _reload_example(module_name: str) -> Any:
    """Reload an example module and disable email-verification so that newly
    registered users can log in immediately in tests."""
    mod = importlib.import_module(f"examples.{module_name}")
    importlib.reload(mod)
    mod.app.debug = (
        False  # prevents Litestar's debug middleware from swallowing IntegrityError before the custom exception handler
    )
    mod.app.plugins.get(LitestarUsersPlugin)._config.require_verification_on_registration = False
    return mod.app


class TestBasicExample:
    @pytest.fixture(scope="class")
    def app(self) -> Any:
        return _reload_example("basic")

    @pytest.fixture(scope="class")
    def client(self, app: Any) -> Any:
        with _make_client(app) as c:
            yield c

    def test_expected_routes_registered(self, app: Any) -> None:
        paths = _route_paths(app)
        assert "/register" in paths
        assert "/login" in paths
        assert "/users/me" in paths
        assert "/forgot-password" in paths
        assert "/reset-password" in paths
        assert "/verify" in paths

    def test_register_creates_user(self, client: Any) -> None:
        response = client.post(
            "/register",
            json={"email": "alice@example.com", "password": "s3cr3tPass!", "title": "Ms"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "alice@example.com"
        assert "password" not in body
        assert "password_hash" not in body
        assert body.get("id") is not None

    def test_register_duplicate_rejected(self, client: Any) -> None:
        client.post("/register", json={"email": "dup@example.com", "password": "pass1234", "title": "Dr"})
        response = client.post("/register", json={"email": "dup@example.com", "password": "pass1234", "title": "Dr"})
        assert response.status_code == 409

    def test_login_after_register(self, client: Any) -> None:
        client.post("/register", json={"email": "bob@example.com", "password": "hunter2!", "title": "Mr"})
        response = client.post("/login", json={"email": "bob@example.com", "password": "hunter2!"})
        assert response.status_code == 201

    def test_login_wrong_password(self, client: Any) -> None:
        client.post("/register", json={"email": "carol@example.com", "password": "correct!", "title": "Mrs"})
        response = client.post("/login", json={"email": "carol@example.com", "password": "wrong!"})
        assert response.status_code == 401


class TestWithRolesExample:
    @pytest.fixture(scope="class")
    def app(self) -> Any:
        return _reload_example("with_roles")

    @pytest.fixture(scope="class")
    def client(self, app: Any) -> Any:
        with _make_client(app) as c:
            yield c

    def test_expected_routes_registered(self, app: Any) -> None:
        paths = _route_paths(app)
        assert "/register" in paths
        assert "/login" in paths
        assert "/users/me" in paths
        assert "/users/roles/assign" in paths
        assert "/users/roles/revoke" in paths

    def test_register_creates_user(self, client: Any) -> None:
        response = client.post(
            "/register",
            json={"email": "alice@roles.com", "password": "s3cr3t!", "title": "Ms"},
        )
        assert response.status_code == 201
        body = response.json()
        assert "password_hash" not in body
        assert "roles" in body

    def test_login_after_register(self, client: Any) -> None:
        client.post("/register", json={"email": "bob@roles.com", "password": "hunter2!", "title": "Mr"})
        response = client.post("/login", json={"email": "bob@roles.com", "password": "hunter2!"})
        assert response.status_code == 201


class TestWithOAuth2Example:
    @pytest.fixture(scope="class")
    def app(self) -> Any:
        return _reload_example("with_oauth2")

    @pytest.fixture(scope="class")
    def client(self, app: Any) -> Any:
        with _make_client(app) as c:
            yield c

    def test_expected_routes_registered(self, app: Any) -> None:
        paths = _route_paths(app)
        assert "/register" in paths
        assert "/login" in paths
        assert "/users/me" in paths
        assert "/oauth2/google/authorize" in paths

    def test_register_creates_user(self, client: Any) -> None:
        response = client.post(
            "/register",
            json={"email": "alice@oauth.com", "password": "s3cr3t!", "title": "Ms"},
        )
        assert response.status_code == 201
        body = response.json()
        assert "password_hash" not in body
        assert "oauth_accounts" in body

    def test_login_after_register(self, client: Any) -> None:
        client.post("/register", json={"email": "bob@oauth.com", "password": "hunter2!", "title": "Mr"})
        response = client.post("/login", json={"email": "bob@oauth.com", "password": "hunter2!"})
        assert response.status_code == 201
