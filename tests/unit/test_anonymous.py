"""Tests for litestar-users authentication middleware.

No database is required.  User lookup is handled by simple in-memory mock
functions injected via monkeypatching, so these tests run without Docker.
"""

import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import pytest
from litestar import Litestar, get
from litestar.di import Provide
from litestar.middleware.base import DefineMiddleware
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.security.jwt.token import Token
from litestar.testing import TestClient
from litestar.types import Empty

import jwt as pyjwt
from litestar_users import (
    AnonymousUser,
    JWTAuthConfig,
    JWTCookieAuthConfig,
    no_validation,
    provide_current_user,
)
from litestar_users.middleware import (
    LitestarUsersJWTCookieMiddleware,
    LitestarUsersJWTMiddleware,
    LitestarUsersSessionMiddlewareWrapper,
)
from litestar_users.middleware import jwt as jwt_mw
from litestar_users.middleware import session as session_mw


def _log_exception(exc: Exception, scope: Any) -> None:
    traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)


SECRET = "1234567890abcdef"
MOCK_USER_ID = "2a8c0e81-4b3e-4c7a-9b51-1234567890ab"


@dataclass
class MockUser:
    id: str
    email: str
    is_active: bool = True
    is_verified: bool = True
    roles: list = field(default_factory=list)
    oauth_accounts: list = field(default_factory=list)


MOCK_USER = MockUser(id=MOCK_USER_ID, email="user@example.com")


def make_valid_token(sub: str = MOCK_USER_ID) -> str:
    token = Token(exp=datetime.now(timezone.utc) + timedelta(days=1), sub=sub)
    return token.encode(secret=SECRET, algorithm="HS256")


def make_expired_token() -> str:
    """Encode an expired JWT directly (bypassing Litestar's future-exp guard)."""
    return pyjwt.encode(
        {"sub": MOCK_USER_ID, "exp": datetime.now(timezone.utc) - timedelta(minutes=5)},
        SECRET,
        algorithm="HS256",
    )


def _me_handler_anonymous_ok() -> Any:
    """Route that accepts both authenticated and anonymous users."""

    @get("/me", sync_to_thread=False)
    def handler(current_user: Annotated[MockUser | AnonymousUser, no_validation]) -> dict:
        return {
            "is_anonymous": isinstance(current_user, AnonymousUser),
        }

    return handler


def _me_handler_auth_required() -> Any:
    """Route that requires an authenticated user."""

    @get("/me", sync_to_thread=False)
    def handler(current_user: MockUser) -> dict:
        return {
            "is_anonymous": isinstance(current_user, AnonymousUser),
        }

    return handler


def _build_jwt_app(
    auth_config: JWTAuthConfig,
    mock_user_lookup: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    anonymous_ok: bool,
) -> Litestar:
    monkeypatch.setattr(jwt_mw, "_get_user_from_sub", mock_user_lookup)

    handler = _me_handler_anonymous_ok() if anonymous_ok else _me_handler_auth_required()

    if isinstance(auth_config, JWTCookieAuthConfig):
        middleware = DefineMiddleware(
            LitestarUsersJWTCookieMiddleware,
            algorithm=auth_config.algorithm,
            auth_header=auth_config.auth_header,
            cookie_key=auth_config.cookie_key,
            token_secret=SECRET,
            exclude=["/schema"],
            exclude_from_auth_key="exclude_from_auth",
            exclude_http_methods=["OPTIONS", "HEAD"],
            scopes=None,
        )
    else:
        middleware = DefineMiddleware(
            LitestarUsersJWTMiddleware,
            algorithm=auth_config.algorithm,
            auth_header=auth_config.auth_header,
            token_secret=SECRET,
            exclude=["/schema"],
            exclude_from_auth_key="exclude_from_auth",
            exclude_http_methods=["OPTIONS", "HEAD"],
            scopes=None,
        )

    return Litestar(
        debug=True,
        after_exception=[_log_exception],
        route_handlers=[handler],
        middleware=[middleware],
        dependencies={"current_user": Provide(provide_current_user, sync_to_thread=False)},
    )


def _build_session_app(
    auth_config: ServerSideSessionConfig,
    mock_user_lookup: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    anonymous_ok: bool,
) -> Litestar:
    monkeypatch.setattr(session_mw, "_get_user_from_session", mock_user_lookup)

    handler = _me_handler_anonymous_ok() if anonymous_ok else _me_handler_auth_required()

    middleware = DefineMiddleware(
        LitestarUsersSessionMiddlewareWrapper,
        session_backend_config=auth_config,
        exclude=["/schema"],
        exclude_from_auth_key="exclude_from_auth",
        exclude_http_methods=["OPTIONS", "HEAD"],
        scopes=None,
    )
    return Litestar(
        debug=True,
        after_exception=[_log_exception],
        route_handlers=[handler],
        middleware=[middleware],
        dependencies={"current_user": Provide(provide_current_user, sync_to_thread=False)},
    )


class TestAnonymousUser:
    def test_defaults(self) -> None:
        user = AnonymousUser()
        assert user.id is Empty
        assert user.is_active is False
        assert user.is_verified is False
        assert user.roles == []
        assert user.oauth_accounts == []

    def test_isinstance_check(self) -> None:
        assert isinstance(AnonymousUser(), AnonymousUser)
        assert not isinstance(MOCK_USER, AnonymousUser)


class TestLitestarUsersJWTMiddleware:
    async def _lookup(self, sub: str, connection: Any) -> Any:
        return MOCK_USER if sub == MOCK_USER_ID else None

    def test_no_auth_header_is_anonymous(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTAuthConfig(), self._lookup, monkeypatch, anonymous_ok=True)
        with TestClient(app) as client:
            response = client.get("/me")
        assert response.status_code == 200
        assert response.json() == {"is_anonymous": True}

    def test_no_auth_header_returns_401_when_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me")
        assert response.status_code == 401

    def test_valid_token_returns_authenticated_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": f"Bearer {make_valid_token()}"})
        assert response.status_code == 200
        assert response.json() == {"is_anonymous": False}

    def test_malformed_token_returns_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": "Bearer not-a-real-token"})
        assert response.status_code == 401

    def test_expired_token_returns_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": f"Bearer {make_expired_token()}"})
        assert response.status_code == 401

    def test_token_for_unknown_user_returns_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": f"Bearer {make_valid_token(sub='nobody')}"})
        assert response.status_code == 401


class TestLitestarUsersJWTCookieMiddleware:
    async def _lookup(self, sub: str, connection: Any) -> Any:
        return MOCK_USER if sub == MOCK_USER_ID else None

    def test_no_credentials_is_anonymous(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTCookieAuthConfig(), self._lookup, monkeypatch, anonymous_ok=True)
        with TestClient(app) as client:
            response = client.get("/me")
        assert response.status_code == 200
        assert response.json() == {"is_anonymous": True}

    def test_no_credentials_returns_401_when_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTCookieAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me")
        assert response.status_code == 401

    def test_valid_header_token_returns_authenticated_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTCookieAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": f"Bearer {make_valid_token()}"})
        assert response.json() == {"is_anonymous": False}

    def test_valid_cookie_token_returns_authenticated_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTCookieAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            client.cookies.set("token", make_valid_token())
            response = client.get("/me")
        assert response.json() == {"is_anonymous": False}

    def test_malformed_token_returns_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTCookieAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": "Bearer garbage"})
        assert response.status_code == 401

    def test_token_for_unknown_user_returns_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _build_jwt_app(JWTCookieAuthConfig(), self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app) as client:
            response = client.get("/me", headers={"Authorization": f"Bearer {make_valid_token(sub='no-such-user')}"})
        assert response.status_code == 401


class TestLitestarUsersSessionMiddleware:
    async def _lookup(self, session_data: dict, connection: Any) -> Any:
        return MOCK_USER if session_data.get("user_id") == MOCK_USER_ID else None

    def test_no_session_is_anonymous(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = ServerSideSessionConfig()
        app = _build_session_app(config, self._lookup, monkeypatch, anonymous_ok=True)
        with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
            response = client.get("/me")
        assert response.status_code == 200
        assert response.json() == {"is_anonymous": True}

    def test_no_session_returns_401_when_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = ServerSideSessionConfig()
        app = _build_session_app(config, self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
            response = client.get("/me")
        assert response.status_code == 401

    def test_valid_session_returns_authenticated_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = ServerSideSessionConfig()
        app = _build_session_app(config, self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
            client.set_session_data({"user_id": MOCK_USER_ID})
            response = client.get("/me")
        assert response.json() == {"is_anonymous": False}

    def test_stale_session_is_anonymous(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Session data present but user not found — treated as anonymous."""
        config = ServerSideSessionConfig()
        app = _build_session_app(config, self._lookup, monkeypatch, anonymous_ok=True)
        with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
            client.set_session_data({"user_id": "deleted-user-id"})
            response = client.get("/me")
        assert response.json() == {"is_anonymous": True}

    def test_stale_session_returns_401_when_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = ServerSideSessionConfig()
        app = _build_session_app(config, self._lookup, monkeypatch, anonymous_ok=False)
        with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
            client.set_session_data({"user_id": "deleted-user-id"})
            response = client.get("/me")
        assert response.status_code == 401

    def test_stale_session_is_cleared(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Stale session data is wiped so it isn't carried forward."""
        config = ServerSideSessionConfig()
        app = _build_session_app(config, self._lookup, monkeypatch, anonymous_ok=True)
        with TestClient(app=app, session_config=ServerSideSessionConfig()) as client:
            client.set_session_data({"user_id": "deleted-user-id"})
            client.get("/me")
            assert client.get_session_data() == {}
