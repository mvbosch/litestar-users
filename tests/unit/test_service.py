"""Unit tests for BaseUserService.

All database I/O is replaced with AsyncMock so no database is needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from advanced_alchemy.exceptions import IntegrityError, NotFoundError
from litestar.exceptions import HTTPException, ImproperlyConfiguredException
from litestar.security.jwt.token import Token

from litestar_users.exceptions import InvalidTokenException
from litestar_users.password import PasswordManager
from litestar_users.schema import OAuth2AuthorizeSchema
from litestar_users.service import BaseUserService, generate_state_token

SECRET = "super-secret-key-32-bytes-long!!"
ENCODING_SECRET = SECRET


def _make_service(
    *,
    user_exists: bool = False,
    stored_user: Any = None,
    role_repository: Any = None,
    oauth2_repository: Any = None,
    require_verification_on_registration: bool = True,
) -> tuple[BaseUserService, MagicMock, MagicMock]:
    """Build a BaseUserService backed entirely by mocks."""
    user_model = MagicMock()
    user_model.__name__ = "User"

    user_repo = AsyncMock()
    user_repo.model_type = user_model
    user_repo.exists = AsyncMock(return_value=user_exists)
    if stored_user is not None:
        user_repo.get_one = AsyncMock(return_value=stored_user)
        user_repo.get = AsyncMock(return_value=stored_user)
        user_repo.get_one_or_none = AsyncMock(return_value=stored_user)
        user_repo.add = AsyncMock(return_value=stored_user)
        user_repo.update = AsyncMock(return_value=stored_user)
        user_repo.delete = AsyncMock(return_value=stored_user)
    else:
        user_repo.add = AsyncMock(return_value=MagicMock())
        user_repo.update = AsyncMock(return_value=MagicMock())
        user_repo.delete = AsyncMock(return_value=MagicMock())
        user_repo.get_one_or_none = AsyncMock(return_value=None)

    service: BaseUserService[Any, Any, Any] = BaseUserService(
        secret=SECRET,
        user_auth_identifier="email",
        user_repository=user_repo,
        hash_schemes=["argon2"],
        role_repository=role_repository,
        oauth2_repository=oauth2_repository,
        require_verification_on_registration=require_verification_on_registration,
    )
    return service, user_repo, user_model


def _make_user(email: str = "user@example.com", password_hash: str = "") -> MagicMock:
    user = MagicMock()
    user.id = uuid4()
    user.email = email
    user.password_hash = password_hash
    user.is_active = True
    user.is_verified = True
    user.roles = []
    return user


def _valid_token(user_id: Any, aud: str) -> str:
    token = Token(
        exp=datetime.now(timezone.utc) + timedelta(hours=1),
        sub=str(user_id),
        aud=aud,
    )
    return token.encode(secret=SECRET, algorithm="HS256")


def test_generate_state_token_sets_aud() -> None:
    data: dict[str, str] = {"sub": "abc"}
    token_str = generate_state_token(data, SECRET)
    assert token_str  # non-empty
    assert data["aud"] == "litestar-users:oauth2-state"


@pytest.mark.asyncio
async def test_add_user_success() -> None:
    user = _make_user()
    service, user_repo, _ = _make_service(user_exists=False, stored_user=user)

    result = await service.add_user(user, verify=True, activate=True)

    user_repo.add.assert_called_once_with(user)
    assert user.is_verified is True
    assert user.is_active is True
    assert result is user


@pytest.mark.asyncio
async def test_add_user_raises_on_duplicate() -> None:
    user = _make_user()
    service, _, _ = _make_service(user_exists=True, stored_user=user)

    with pytest.raises(IntegrityError):
        await service.add_user(user)


@pytest.mark.asyncio
async def test_add_user_inactive_unverified_by_default() -> None:
    user = _make_user()
    service, _, _ = _make_service(user_exists=False, stored_user=user)

    await service.add_user(user)

    assert user.is_verified is False
    assert user.is_active is True  # default activate=True


@pytest.mark.asyncio
async def test_get_user() -> None:
    user = _make_user()
    service, user_repo, _ = _make_service(stored_user=user)

    result = await service.get_user(user.id)

    user_repo.get.assert_called_once_with(user.id, load=None, execution_options=None)
    assert result is user


@pytest.mark.asyncio
async def test_get_user_by_returns_none_when_not_found() -> None:
    service, user_repo, _ = _make_service()
    user_repo.get_one_or_none = AsyncMock(return_value=None)

    result = await service.get_user_by(email="nobody@example.com")

    assert result is None


@pytest.mark.asyncio
async def test_delete_user() -> None:
    user = _make_user()
    service, user_repo, _ = _make_service(stored_user=user)

    result = await service.delete_user(user.id)

    user_repo.delete.assert_called_once_with(user.id)
    assert result is user


@pytest.mark.asyncio
async def test_list_and_count_users() -> None:
    user = _make_user()
    service, user_repo, _ = _make_service()
    user_repo.list_and_count = AsyncMock(return_value=([user], 1))

    users, count = await service.list_and_count_users()

    assert count == 1
    assert users[0] is user


@pytest.mark.asyncio
async def test_update_user_hashes_password() -> None:
    user = _make_user(password_hash="plaintext-password")
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.update = AsyncMock(return_value=user)

    await service.update_user(user)

    # password_hash should have been replaced with a hash (not the original)
    assert user.password_hash != "plaintext-password"
    user_repo.update.assert_called_once_with(user)


@pytest.mark.asyncio
async def test_update_user_empty_password_not_hashed() -> None:
    user = _make_user(password_hash="")
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.update = AsyncMock(return_value=user)

    await service.update_user(user)

    assert user.password_hash == ""  # falsy — not touched


@pytest.mark.asyncio
async def test_authenticate_success() -> None:

    pm = PasswordManager(hash_schemes=["argon2"])
    hashed = pm.hash("correct-password")

    user = _make_user(email="a@b.com", password_hash=hashed)
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.get_one = AsyncMock(return_value=user)

    data = MagicMock()
    data.email = "a@b.com"
    data.password = "correct-password"

    result = await service.authenticate(data)

    assert result is user


@pytest.mark.asyncio
async def test_authenticate_wrong_password() -> None:

    pm = PasswordManager(hash_schemes=["argon2"])
    hashed = pm.hash("correct-password")

    user = _make_user(email="a@b.com", password_hash=hashed)
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.get_one = AsyncMock(return_value=user)

    data = MagicMock()
    data.email = "a@b.com"
    data.password = "wrong-password"

    result = await service.authenticate(data)

    assert result is None


@pytest.mark.asyncio
async def test_authenticate_user_not_found() -> None:
    service, user_repo, _ = _make_service()
    user_repo.get_one = AsyncMock(side_effect=NotFoundError())

    data = MagicMock()
    data.email = "ghost@example.com"
    data.password = "whatever"

    result = await service.authenticate(data)

    assert result is None


def test_generate_token_encodes_user_id() -> None:
    service, _, _ = _make_service()
    uid = uuid4()
    token_str = service.generate_token(uid, aud="verify")

    decoded = Token.decode(token_str, secret=SECRET, algorithm="HS256")
    assert decoded.sub == str(uid)
    assert decoded.aud == "verify"


def test_decode_and_verify_token_valid() -> None:
    service, _, _ = _make_service()
    uid = uuid4()
    token_str = _valid_token(uid, "verify")

    token = service._decode_and_verify_token(token_str, context="verify")
    assert token.sub == str(uid)


def test_decode_and_verify_token_wrong_aud() -> None:
    service, _, _ = _make_service()
    token_str = _valid_token(uuid4(), "verify")

    with pytest.raises(InvalidTokenException):
        service._decode_and_verify_token(token_str, context="reset_password")


def test_decode_and_verify_token_invalid_jwt() -> None:
    service, _, _ = _make_service()

    with pytest.raises(InvalidTokenException):
        service._decode_and_verify_token("not.a.valid.token", context="verify")


@pytest.mark.asyncio
async def test_verify_uuid_user_id() -> None:
    uid = uuid4()
    user = _make_user()
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.update = AsyncMock(return_value=user)

    token_str = _valid_token(uid, "verify")
    result = await service.verify(token_str)

    assert result is user
    user_repo.update.assert_called_once()


@pytest.mark.asyncio
async def test_verify_integer_user_id() -> None:
    user = _make_user()
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.update = AsyncMock(return_value=user)

    # Use an integer id (not a valid UUID string)
    token = Token(
        exp=datetime.now(timezone.utc) + timedelta(hours=1),
        sub="42",
        aud="verify",
    )
    token_str = token.encode(secret=SECRET, algorithm="HS256")
    result = await service.verify(token_str)

    assert result is user


@pytest.mark.asyncio
async def test_verify_not_found_raises_invalid_token() -> None:
    uid = uuid4()
    service, user_repo, _ = _make_service()
    user_repo.update = AsyncMock(side_effect=NotFoundError())

    token_str = _valid_token(uid, "verify")
    with pytest.raises(InvalidTokenException):
        await service.verify(token_str)


@pytest.mark.asyncio
async def test_initiate_password_reset_user_not_found_still_succeeds() -> None:
    """Should not leak whether user exists."""
    service, user_repo, _ = _make_service()
    user_repo.get_one_or_none = AsyncMock(return_value=None)

    # Should not raise
    await service.initiate_password_reset("nobody@example.com")


@pytest.mark.asyncio
async def test_initiate_password_reset_calls_send_token(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _make_user()
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.get_one_or_none = AsyncMock(return_value=user)

    mock_send = AsyncMock()
    monkeypatch.setattr(service, "send_password_reset_token", mock_send)

    await service.initiate_password_reset(user.email)

    mock_send.assert_called_once()


@pytest.mark.asyncio
async def test_reset_password_updates_hash() -> None:
    uid = uuid4()
    user = _make_user()
    service, user_repo, _ = _make_service(stored_user=user)
    user_repo.update = AsyncMock(return_value=user)

    token_str = _valid_token(uid, "reset_password")
    await service.reset_password(token_str, "new-password")

    user_repo.update.assert_called_once()


@pytest.mark.asyncio
async def test_reset_password_invalid_token_raises() -> None:
    service, _, _ = _make_service()

    with pytest.raises(InvalidTokenException):
        await service.reset_password("bad.token.here", "new-password")


@pytest.mark.asyncio
async def test_reset_password_user_not_found_raises() -> None:
    uid = uuid4()
    service, user_repo, _ = _make_service()
    user_repo.update = AsyncMock(side_effect=NotFoundError())

    token_str = _valid_token(uid, "reset_password")
    with pytest.raises(InvalidTokenException):
        await service.reset_password(token_str, "new-password")


@pytest.mark.asyncio
async def test_get_role_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.get_role(uuid4())


@pytest.mark.asyncio
async def test_add_role_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.add_role(MagicMock())


@pytest.mark.asyncio
async def test_delete_role_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.delete_role(uuid4())


@pytest.mark.asyncio
async def test_assign_role_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.assign_role(uuid4(), uuid4())


@pytest.mark.asyncio
async def test_revoke_role_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.revoke_role(uuid4(), uuid4())


@pytest.mark.asyncio
async def test_list_and_count_roles_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.list_and_count_roles()


@pytest.mark.asyncio
async def test_get_role_by_name_raises_without_role_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.get_role_by_name("admin")


def _make_role_repo(role: Any = None) -> AsyncMock:
    repo = AsyncMock()
    repo.model_type = MagicMock()
    repo.get = AsyncMock(return_value=role or MagicMock())
    repo.get_one = AsyncMock(return_value=role or MagicMock())
    repo.add = AsyncMock(return_value=role or MagicMock())
    repo.update = AsyncMock(return_value=role or MagicMock())
    repo.delete = AsyncMock(return_value=role or MagicMock())
    repo.list_and_count = AsyncMock(return_value=([], 0))
    repo.assign_role = AsyncMock()
    repo.revoke_role = AsyncMock()
    return repo


@pytest.mark.asyncio
async def test_add_role_success() -> None:
    role = MagicMock()
    role_repo = _make_role_repo(role)
    role_repo.add = AsyncMock(return_value=role)

    service, _, _ = _make_service(role_repository=role_repo)

    result = await service.add_role(role)

    role_repo.add.assert_called_once_with(role)
    assert result is role


@pytest.mark.asyncio
async def test_assign_role_already_has_role_raises() -> None:
    role = MagicMock()
    role.name = "admin"
    user = _make_user()
    user.roles = [role]
    user.id = uuid4()

    role_repo = _make_role_repo(role)
    service, _, _ = _make_service(stored_user=user, role_repository=role_repo)

    with pytest.raises(IntegrityError):
        await service.assign_role(user.id, uuid4())


@pytest.mark.asyncio
async def test_assign_role_no_roles_attr_raises() -> None:
    role = MagicMock()
    user = MagicMock(spec=[])  # no 'roles' attr
    user.id = uuid4()

    role_repo = _make_role_repo(role)
    service, _, _ = _make_service(stored_user=user, role_repository=role_repo)

    with pytest.raises(ImproperlyConfiguredException):
        await service.assign_role(user.id, uuid4())


@pytest.mark.asyncio
async def test_revoke_role_not_present_raises() -> None:
    role = MagicMock()
    role.name = "admin"
    user = _make_user()
    user.roles = []  # role is NOT present
    user.id = uuid4()

    role_repo = _make_role_repo(role)
    service, _, _ = _make_service(stored_user=user, role_repository=role_repo)

    with pytest.raises(IntegrityError):
        await service.revoke_role(user.id, uuid4())


@pytest.mark.asyncio
async def test_get_by_oauth_account_raises_without_oauth_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.get_by_oauth_account("google", "123")


@pytest.mark.asyncio
async def test_oauth2_authorize_raises_without_oauth_repository() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.oauth2_authorize(
            request=MagicMock(),
            oauth_client=MagicMock(),
            state_secret=SECRET,
            callback_route_name="callback",
        )


@pytest.mark.asyncio
async def test_pre_login_hook_returns_true() -> None:
    service, _, _ = _make_service()
    result = await service.pre_login_hook(MagicMock())
    assert result is True


@pytest.mark.asyncio
async def test_post_login_hook_returns_none() -> None:
    service, _, _ = _make_service()
    await service.post_login_hook(MagicMock())


@pytest.mark.asyncio
async def test_pre_registration_hook_returns_none() -> None:
    service, _, _ = _make_service()
    await service.pre_registration_hook({})


@pytest.mark.asyncio
async def test_post_registration_hook_returns_none() -> None:
    service, _, _ = _make_service()
    await service.post_registration_hook(MagicMock())


@pytest.mark.asyncio
async def test_post_verification_hook_returns_none() -> None:
    service, _, _ = _make_service()
    await service.post_verification_hook(MagicMock())


@pytest.mark.asyncio
async def test_send_verification_token_returns_none() -> None:
    service, _, _ = _make_service()
    await service.send_verification_token(MagicMock(), "token")


@pytest.mark.asyncio
async def test_send_password_reset_token_returns_none() -> None:
    service, _, _ = _make_service()
    await service.send_password_reset_token(MagicMock(), "token")


def _make_oauth2_repo(oauth_account: Any = None) -> AsyncMock:
    repo = AsyncMock()
    repo.model_type = MagicMock()
    repo.get_one = AsyncMock(return_value=oauth_account)
    repo.add = AsyncMock(return_value=MagicMock())
    repo.update = AsyncMock(return_value=MagicMock())
    return repo


@pytest.mark.asyncio
async def test_get_by_oauth_account_raises_without_repo() -> None:
    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.get_by_oauth_account("google", "123")


@pytest.mark.asyncio
async def test_get_by_oauth_account_success() -> None:
    user = _make_user()
    oauth_account = MagicMock()
    oauth_account.user_id = user.id

    oauth_repo = _make_oauth2_repo(oauth_account)
    service, _, _ = _make_service(stored_user=user, oauth2_repository=oauth_repo)

    result = await service.get_by_oauth_account("google", "123")

    assert result is user
    oauth_repo.get_one.assert_called_once_with(oauth_name="google", account_id="123")


@pytest.mark.asyncio
async def test_get_by_oauth_account_not_found_raises() -> None:
    oauth_repo = _make_oauth2_repo(oauth_account=None)
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    with pytest.raises(NotFoundError):
        await service.get_by_oauth_account("google", "missing")


@pytest.mark.asyncio
async def test_oauth2_callback_internal_invalid_state_raises() -> None:
    """Bad state JWT → HTTPException 400."""
    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    with pytest.raises(HTTPException) as exc_info:
        await service._oauth2_callback(
            oauth_name="google",
            account_id="123",
            account_email="a@b.com",
            associate_by_email=False,
            is_verified_by_default=False,
            state="not.a.valid.state",
            state_secret=SECRET,
            oauth_account_dict={},
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_oauth2_callback_internal_updates_existing_oauth_account() -> None:
    """User already has this OAuth account → update it."""
    user = _make_user()
    existing_acc = MagicMock()
    existing_acc.account_id = "acc-123"
    existing_acc.oauth_name = "google"
    user.oauth_accounts = [existing_acc]

    oauth_repo = _make_oauth2_repo()
    # get_one returns the existing oauth account (user found)
    oauth_repo.get_one = AsyncMock(return_value=existing_acc)
    # get of user returns user
    service, _, _ = _make_service(stored_user=user, oauth2_repository=oauth_repo)

    state = generate_state_token({}, SECRET)
    await service._oauth2_callback(
        oauth_name="google",
        account_id="acc-123",
        account_email=user.email,
        associate_by_email=False,
        is_verified_by_default=False,
        state=state,
        state_secret=SECRET,
        oauth_account_dict={"access_token": "NEW_TOKEN"},
    )

    oauth_repo.update.assert_called_once()


@pytest.mark.asyncio
async def test_oauth2_callback_internal_associates_existing_user_by_email() -> None:
    """No existing OAuth account, but user with same email exists → associate."""
    user = _make_user(email="a@b.com")
    user.oauth_accounts = []

    oauth_repo = _make_oauth2_repo()
    # simulate: get_by_oauth_account raises NotFoundError (no existing oauth account)
    oauth_repo.get_one = AsyncMock(side_effect=NotFoundError())
    service, user_repo, _ = _make_service(stored_user=user, oauth2_repository=oauth_repo)
    user_repo.get_one_or_none = AsyncMock(return_value=user)

    state = generate_state_token({}, SECRET)
    await service._oauth2_callback(
        oauth_name="google",
        account_id="new-acc",
        account_email="a@b.com",
        associate_by_email=True,
        is_verified_by_default=False,
        state=state,
        state_secret=SECRET,
        oauth_account_dict={"access_token": "TOKEN"},
    )

    oauth_repo.add.assert_called_once()


@pytest.mark.asyncio
async def test_oauth2_callback_internal_creates_new_user_when_associate_by_email() -> None:
    """No existing OAuth account, no user with that email, associate_by_email=True → create user."""
    oauth_repo = _make_oauth2_repo()
    oauth_repo.get_one = AsyncMock(side_effect=NotFoundError())

    new_user = _make_user(email="new@b.com")
    service, user_repo, _ = _make_service(oauth2_repository=oauth_repo)
    user_repo.get_one_or_none = AsyncMock(return_value=None)
    user_repo.add = AsyncMock(return_value=new_user)

    state = generate_state_token({}, SECRET)
    await service._oauth2_callback(
        oauth_name="google",
        account_id="new-acc",
        account_email="new@b.com",
        associate_by_email=True,
        is_verified_by_default=True,
        state=state,
        state_secret=SECRET,
        oauth_account_dict={"access_token": "TOKEN"},
    )

    user_repo.add.assert_called_once()
    oauth_repo.add.assert_called_once()


@pytest.mark.asyncio
async def test_oauth2_callback_internal_raises_when_not_associate_by_email_and_no_user() -> None:
    """No existing OAuth account, no matching user, associate_by_email=False → HTTPException 400."""

    oauth_repo = _make_oauth2_repo()
    oauth_repo.get_one = AsyncMock(side_effect=NotFoundError())
    service, user_repo, _ = _make_service(oauth2_repository=oauth_repo)
    user_repo.get_one_or_none = AsyncMock(return_value=None)

    state = generate_state_token({}, SECRET)
    with pytest.raises(HTTPException) as exc_info:
        await service._oauth2_callback(
            oauth_name="google",
            account_id="new-acc",
            account_email="new@b.com",
            associate_by_email=False,
            is_verified_by_default=False,
            state=state,
            state_secret=SECRET,
            oauth_account_dict={},
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_oauth2_associate_callback_raises_without_repo() -> None:
    service, _, _ = _make_service()

    with pytest.raises(ImproperlyConfiguredException):
        await service._oauth2_associate_callback(
            associate_user=MagicMock(),
            state="state",
            state_secret=SECRET,
            oauth_account_dict={},
        )


@pytest.mark.asyncio
async def test_oauth2_associate_callback_invalid_state_raises() -> None:

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    with pytest.raises(HTTPException) as exc_info:
        await service._oauth2_associate_callback(
            associate_user=MagicMock(),
            state="bad.state.token",
            state_secret=SECRET,
            oauth_account_dict={},
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_oauth2_associate_callback_sub_mismatch_raises() -> None:

    associate_user = _make_user()
    # State sub is a different UUID
    state = generate_state_token({"sub": str(uuid4())}, SECRET)

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    with pytest.raises(HTTPException) as exc_info:
        await service._oauth2_associate_callback(
            associate_user=associate_user,
            state=state,
            state_secret=SECRET,
            oauth_account_dict={},
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_oauth2_associate_callback_success() -> None:

    associate_user = _make_user()
    state = generate_state_token({"sub": str(associate_user.id)}, SECRET)

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    await service._oauth2_associate_callback(
        associate_user=associate_user,
        state=state,
        state_secret=SECRET,
        oauth_account_dict={"access_token": "TOKEN"},
    )

    oauth_repo.add.assert_called_once()


@pytest.mark.asyncio
async def test_oauth2_authorize_raises_without_repo() -> None:

    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.oauth2_authorize(
            request=MagicMock(),
            oauth_client=MagicMock(),
            state_secret=SECRET,
            callback_route_name="callback",
        )


@pytest.mark.asyncio
async def test_oauth2_authorize_with_explicit_redirect_url() -> None:

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    oauth_client = AsyncMock()
    oauth_client.get_authorization_url = AsyncMock(return_value="https://provider.com/auth?state=X")

    request = MagicMock()

    result = await service.oauth2_authorize(
        request=request,
        oauth_client=oauth_client,
        state_secret=SECRET,
        callback_route_name="callback",
        redirect_url="https://myapp.com/callback",
    )

    assert isinstance(result, OAuth2AuthorizeSchema)
    assert result.authorization_url == "https://provider.com/auth?state=X"
    oauth_client.get_authorization_url.assert_called_once()
    # redirect_url was passed as the first positional arg
    call_args = oauth_client.get_authorization_url.call_args
    assert call_args[0][0] == "https://myapp.com/callback"


@pytest.mark.asyncio
async def test_oauth2_authorize_derives_redirect_from_request() -> None:

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    oauth_client = AsyncMock()
    oauth_client.get_authorization_url = AsyncMock(return_value="https://provider.com/auth")

    request = MagicMock()
    request.url_for = MagicMock(return_value="https://myapp.com/derived-callback")

    result = await service.oauth2_authorize(
        request=request,
        oauth_client=oauth_client,
        state_secret=SECRET,
        callback_route_name="callback",
    )

    assert isinstance(result, OAuth2AuthorizeSchema)
    request.url_for.assert_called_once_with("callback")


@pytest.mark.asyncio
async def test_oauth2_callback_outer_raises_without_repo() -> None:

    service, _, _ = _make_service()
    with pytest.raises(ImproperlyConfiguredException):
        await service.oauth2_callback(
            data={},
            oauth_client=MagicMock(),
            state_secret=SECRET,
            callback_route_name="callback",
            request=MagicMock(),
        )


@pytest.mark.asyncio
async def test_oauth2_callback_outer_raises_when_email_is_none() -> None:

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    oauth_client = AsyncMock()
    token = {"access_token": "TOKEN"}
    oauth_client.get_access_token = AsyncMock(return_value=token)
    oauth_client.get_id_email = AsyncMock(return_value=("acc-123", None))  # no email
    oauth_client.name = "google"

    request = MagicMock()
    request.url_for = MagicMock(return_value="https://myapp.com/callback")

    state = generate_state_token({}, SECRET)

    with pytest.raises(HTTPException) as exc_info:
        await service.oauth2_callback(
            data={"code": "CODE", "code_verifier": None, "state": state},
            oauth_client=oauth_client,
            state_secret=SECRET,
            callback_route_name="callback",
            request=request,
        )
    assert exc_info.value.status_code == 400
    assert "email" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_oauth2_callback_outer_associate_path() -> None:
    """is_associate_callback=True delegates to _oauth2_associate_callback."""
    user = _make_user()

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(stored_user=user, oauth2_repository=oauth_repo)

    oauth_client = AsyncMock()
    token = {"access_token": "TOKEN"}
    oauth_client.get_access_token = AsyncMock(return_value=token)
    oauth_client.get_id_email = AsyncMock(return_value=("acc-123", user.email))
    oauth_client.name = "google"

    request = MagicMock()
    request.url_for = MagicMock(return_value="https://myapp.com/callback")

    state = generate_state_token({"sub": str(user.id)}, SECRET)

    await service.oauth2_callback(
        data={"code": "CODE", "code_verifier": None, "state": state},
        oauth_client=oauth_client,
        state_secret=SECRET,
        callback_route_name="callback",
        request=request,
        is_associate_callback=True,
        associate_user=user,
    )

    oauth_repo.add.assert_called_once()


@pytest.mark.asyncio
async def test_oauth2_callback_outer_associate_path_raises_when_no_associate_user() -> None:
    """is_associate_callback=True but associate_user=None → HTTPException."""

    oauth_repo = _make_oauth2_repo()
    service, _, _ = _make_service(oauth2_repository=oauth_repo)

    oauth_client = AsyncMock()
    token = {"access_token": "TOKEN"}
    oauth_client.get_access_token = AsyncMock(return_value=token)
    oauth_client.get_id_email = AsyncMock(return_value=("acc-123", "a@b.com"))
    oauth_client.name = "google"

    request = MagicMock()
    request.url_for = MagicMock(return_value="https://myapp.com/callback")

    state = generate_state_token({}, SECRET)

    with pytest.raises(HTTPException) as exc_info:
        await service.oauth2_callback(
            data={"code": "CODE", "code_verifier": None, "state": state},
            oauth_client=oauth_client,
            state_secret=SECRET,
            callback_route_name="callback",
            request=request,
            is_associate_callback=True,
            associate_user=None,
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_oauth2_callback_outer_regular_path() -> None:
    """Regular (non-associate) path delegates to _oauth2_callback."""
    user = _make_user()
    existing_acc = MagicMock()
    existing_acc.account_id = "acc-123"
    existing_acc.oauth_name = "google"
    user.oauth_accounts = [existing_acc]

    oauth_repo = _make_oauth2_repo()
    # existing oauth account found so update path taken
    oauth_repo.get_one = AsyncMock(return_value=existing_acc)
    service, _, _ = _make_service(stored_user=user, oauth2_repository=oauth_repo)

    oauth_client = AsyncMock()
    token = {"access_token": "TOKEN"}
    oauth_client.get_access_token = AsyncMock(return_value=token)
    oauth_client.get_id_email = AsyncMock(return_value=("acc-123", user.email))
    oauth_client.name = "google"

    request = MagicMock()
    request.url_for = MagicMock(return_value="https://myapp.com/callback")

    state = generate_state_token({}, SECRET)

    await service.oauth2_callback(
        data={"code": "CODE", "code_verifier": None, "state": state},
        oauth_client=oauth_client,
        state_secret=SECRET,
        callback_route_name="callback",
        request=request,
    )

    # update called because existing account matched
    oauth_repo.update.assert_called_once()
