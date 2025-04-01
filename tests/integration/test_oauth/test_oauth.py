from typing import TYPE_CHECKING, Any

import pytest
from httpx_oauth.oauth2 import BaseOAuth2
from litestar import status_codes
from litestar.exceptions import HTTPException
from litestar.security.session_auth import SessionAuth

from litestar_users.config import LitestarUsersConfig
from litestar_users.service import generate_state_token
from tests.utils import MockAuth

if TYPE_CHECKING:
    from litestar.testing import TestClient

    from tests.integration.test_oauth.conftest import AsyncMethodMocker, UserService


class TestAuthorize:
    def test_success(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
    ) -> None:
        get_authorization_url_mock, get_authorization_url_reset_mock = async_method_mocker(
            oauth_client, "get_authorization_url", return_value="AUTHORIZATION_URL"
        )

        response = client.get("/oauth2/service1/authorize", params={"scopes": ["scope1", "scope2"]})

        assert response.status_code == 200
        get_authorization_url_mock.assert_called_once()

        data = response.json()
        assert "authorization_url" in data
        get_authorization_url_reset_mock()

    def test_with_redirect_url(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
    ) -> None:
        get_authorization_url_mock, get_authorization_url_reset_mock = async_method_mocker(
            oauth_client, "get_authorization_url", return_value="AUTHORIZATION_URL"
        )
        response = client.get("/oauth2/service1/authorize", params={"scopes": ["scope1", "scope2"]})

        assert response.status_code == 200
        get_authorization_url_mock.assert_called_once()

        data = response.json()
        assert "authorization_url" in data
        get_authorization_url_reset_mock()


@pytest.mark.parametrize(
    "access_token",
    [
        ({"access_token": "TOKEN", "expires_at": 1579179542}),
        ({"access_token": "TOKEN"}),
    ],
)
class TestCallback:
    async def test_invalid_state(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        access_token: str,
    ) -> None:
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        get_id_email_mock, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )

        response = client.get(
            "/oauth2/service1/callback",
            params={"code": "CODE", "state": "STATE"},
        )
        assert response.status_code == 400

        get_id_email_mock.assert_called_once_with("TOKEN")
        get_id_email_reset_mock()
        get_access_token_reset_mock()

    async def test_already_exists_error(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
    ) -> None:
        state_jwt = generate_state_token({}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )
        oauth2_callback_mock, oauth2_callback_reset_mock = async_method_mocker(user_service, "_oauth2_callback")
        oauth2_callback_mock.side_effect = HTTPException(
            status_code=status_codes.HTTP_400_BAD_REQUEST, detail="User already exists."
        )

        response = client.get(
            "/oauth2/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == 400

        data = response.json()
        assert data["detail"] == "User already exists."
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()

    async def test_active_user(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
        litestar_users_config: LitestarUsersConfig,
    ) -> None:
        state_jwt = generate_state_token({}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )
        _, oauth2_callback_reset_mock = async_method_mocker(user_service, "_oauth2_callback", return_value=generic_user)

        response = client.get(
            "/oauth2/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == 201

        data = response.json()
        assert data["email"] == generic_user.email
        assert data["username"] == generic_user.username
        assert data["id"] == str(generic_user.id)
        if litestar_users_config.auth_backend_class == SessionAuth:
            assert client.get_session_data()["user_id"] == str(generic_user.id)
        else:
            assert "Authorization" in response.headers
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()

    async def test_inactive_user(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        inactive_user: Any,
        user_service: "UserService",
        access_token: str,
    ) -> None:
        state_jwt = generate_state_token({}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(
            oauth_client,
            "get_id_email",
            return_value=("user1", inactive_user.email),
        )
        _, oauth2_callback_reset_mock = async_method_mocker(
            user_service, "_oauth2_callback", return_value=inactive_user
        )

        response = client.get(
            "/oauth2/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"] == "User is not active."
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()

    async def test_redirect_url(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
    ) -> None:
        state_jwt = generate_state_token({}, "SECRET")
        get_access_token_mock, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )
        _, oauth2_callback_reset_mock = async_method_mocker(user_service, "_oauth2_callback", return_value=generic_user)

        response = client.get(
            "/oauth2/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == status_codes.HTTP_201_CREATED

        get_access_token_mock.assert_called_once_with("CODE", "https://testdomain.com/callback_redirect", None)

        data = response.json()
        assert data["email"] == generic_user.email
        assert data["username"] == generic_user.username
        assert data["id"] == str(generic_user.id)
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()

    async def test_email_not_available(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
    ) -> None:
        state_jwt = generate_state_token({}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(oauth_client, "get_id_email", return_value=("user1", None))
        _, oauth2_callback_reset_mock = async_method_mocker(user_service, "_oauth2_callback", return_value=generic_user)

        response = client.get(
            "/oauth2/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == 400
        json = response.json()
        assert json["detail"] == "OAuth account without email"
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()


class TestAssociateAuthorize:
    async def test_missing_token(self, client: "TestClient") -> None:
        response = client.get("/oauth2-associate/service1/authorize", params={"scopes": ["scope1", "scope2"]})

        assert response.status_code == status_codes.HTTP_401_UNAUTHORIZED

    async def test_inactive_user(self, client: "TestClient", inactive_user: Any, mock_auth: MockAuth) -> None:
        mock_auth.authenticate(inactive_user.id)
        response = client.get(
            "/oauth2-associate/service1/authorize",
            params={"scopes": ["scope1", "scope2"]},
        )

        assert response.status_code == status_codes.HTTP_401_UNAUTHORIZED

    async def test_active_user(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        get_authorization_url_mock, get_authorization_url_reset_mock = async_method_mocker(
            oauth_client, "get_authorization_url", return_value="AUTHORIZATION_URL"
        )
        response = client.get(
            "/oauth2-associate/service1/authorize",
            params={"scopes": ["scope1", "scope2"]},
        )

        assert response.status_code == status_codes.HTTP_200_OK
        get_authorization_url_mock.assert_called_once()

        data = response.json()
        assert "authorization_url" in data
        get_authorization_url_reset_mock()

    async def test_with_redirect_url(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        get_authorization_url_mock, get_authorization_url_reset_mock = async_method_mocker(
            oauth_client, "get_authorization_url", return_value="AUTHORIZATION_URL"
        )

        response = client.get(
            "/oauth2-associate/service1/authorize",
            params={"scopes": ["scope1", "scope2"]},
        )

        assert response.status_code == status_codes.HTTP_200_OK
        get_authorization_url_mock.assert_called_once()

        data = response.json()
        assert "authorization_url" in data
        get_authorization_url_reset_mock()


@pytest.mark.parametrize(
    "access_token",
    [
        ({"access_token": "TOKEN", "expires_at": 1579179542}),
        ({"access_token": "TOKEN"}),
    ],
)
class TestAssociateCallback:
    async def test_missing_token(self, client: "TestClient", access_token: str) -> None:
        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": "STATE"},
        )

        assert response.status_code == status_codes.HTTP_401_UNAUTHORIZED

    async def test_active_user(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        state_jwt = generate_state_token({"sub": str(generic_user.id)}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )
        _, oauth2_callback_reset_mock = async_method_mocker(
            user_service, "_oauth2_associate_callback", return_value=generic_user
        )

        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == status_codes.HTTP_201_CREATED

        data = response.json()
        assert data["id"] == str(generic_user.id)
        assert data["email"] == generic_user.email
        assert data["username"] == generic_user.username
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()

    async def test_inactive_user(
        self,
        client: "TestClient",
        inactive_user: Any,
        access_token: str,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(inactive_user.id)
        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": "STATE"},
        )

        assert response.status_code == status_codes.HTTP_401_UNAUTHORIZED

    async def test_invalid_state(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        access_token: str,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        get_id_email_mock, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )

        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": "STATE"},
        )
        assert response.status_code == status_codes.HTTP_400_BAD_REQUEST

        get_id_email_mock.assert_called_once_with("TOKEN")
        get_id_email_reset_mock()
        get_access_token_reset_mock()

    async def test_state_with_different_user_id(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        verified_user: Any,
        access_token: str,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        state_jwt = generate_state_token({"sub": str(verified_user.id)}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        get_id_email_mock, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )

        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )
        assert response.status_code == status_codes.HTTP_400_BAD_REQUEST

        get_id_email_mock.assert_called_once_with("TOKEN")
        get_id_email_reset_mock()
        get_access_token_reset_mock()

    async def test_redirect_url_router(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        state_jwt = generate_state_token({"sub": str(generic_user.id)}, "SECRET")
        get_access_token_mock, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(
            oauth_client, "get_id_email", return_value=("user1", generic_user.email)
        )
        _, oauth2_callback_reset_mock = async_method_mocker(
            user_service, "_oauth2_associate_callback", return_value=generic_user
        )

        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == status_codes.HTTP_201_CREATED

        get_access_token_mock.assert_called_once_with(
            "CODE", "https://testdomain.com/associate_callback_redirect", None
        )

        data = response.json()
        assert data["id"] == str(generic_user.id)
        assert data["email"] == generic_user.email
        assert data["username"] == generic_user.username
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()

    async def test_not_available_email(
        self,
        async_method_mocker: "AsyncMethodMocker",
        client: "TestClient",
        oauth_client: BaseOAuth2,
        generic_user: Any,
        user_service: "UserService",
        access_token: str,
        mock_auth: MockAuth,
    ) -> None:
        mock_auth.authenticate(generic_user.id)
        state_jwt = generate_state_token({"sub": str(generic_user.id)}, "SECRET")
        _, get_access_token_reset_mock = async_method_mocker(
            oauth_client, "get_access_token", return_value=access_token
        )
        _, get_id_email_reset_mock = async_method_mocker(oauth_client, "get_id_email", return_value=("user1", None))
        _, oauth2_callback_reset_mock = async_method_mocker(
            user_service, "_oauth2_associate_callback", return_value=generic_user
        )

        response = client.get(
            "/oauth2-associate/service1/callback",
            params={"code": "CODE", "state": state_jwt},
        )

        assert response.status_code == status_codes.HTTP_400_BAD_REQUEST
        json = response.json()
        assert json["detail"] == "OAuth account without email"
        get_access_token_reset_mock()
        get_id_email_reset_mock()
        oauth2_callback_reset_mock()
