from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from litestar.exceptions import NotAuthorizedException
from litestar.middleware.session.base import BaseBackendConfig
from litestar.security.jwt import Token

from .constants import ENCODING_SECRET

if TYPE_CHECKING:
    from uuid import UUID

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.testing import TestClient

    from litestar_users import LitestarUsersConfig


def create_jwt(identifier: str) -> str:
    token = Token(exp=datetime.now() + timedelta(days=1), sub=identifier)
    return token.encode(secret=ENCODING_SECRET, algorithm="HS256")


class MockAuth:
    """Mock class to be used in authentication fixtures."""

    def __init__(self, client: "TestClient", config: "LitestarUsersConfig") -> None:
        self.client = client
        self.config = config

    def authenticate(self, user_id: "UUID") -> None:
        """Authenticate a TestClient request.

        Works with both session and JWT backends.
        """
        if isinstance(self.config.auth_config, BaseBackendConfig):
            self.client.set_session_data({"user_id": user_id})
        else:
            token = create_jwt(str(user_id))
            self.client.headers["Authorization"] = "Bearer " + token


def basic_guard(connection: "ASGIConnection", _: "BaseRouteHandler") -> None:
    """Authorize a request if the user's email string contains 'admin'."""
    if "admin" in connection.user.email:
        return
    raise NotAuthorizedException()
