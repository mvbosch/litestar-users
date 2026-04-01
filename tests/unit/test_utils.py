"""Unit tests for litestar_users.utils (no database required)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from advanced_alchemy.extensions.litestar.plugins import SQLAlchemyInitPlugin
from litestar.exceptions import ImproperlyConfiguredException
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from litestar_users import LitestarUsersPlugin
from litestar_users.utils import async_session, get_litestar_users_plugin, get_sqlalchemy_plugin, get_user_service


def _make_app(*, with_users_plugin: bool = True, with_sqlalchemy_plugin: bool = True) -> MagicMock:
    """Build a minimal fake Litestar app with pluggable mock plugins."""

    users_plugin = MagicMock(spec=LitestarUsersPlugin)
    users_config = MagicMock()
    users_plugin._config = users_config

    sqlalchemy_plugin = MagicMock(spec=SQLAlchemyInitPlugin)

    def _plugins_get(cls: type) -> Any:
        if cls is LitestarUsersPlugin:
            if not with_users_plugin:
                raise KeyError(cls)
            return users_plugin
        if cls is SQLAlchemyInitPlugin:
            if not with_sqlalchemy_plugin:
                raise KeyError(cls)
            return sqlalchemy_plugin
        raise KeyError(cls)

    app = MagicMock()
    app.plugins.get = _plugins_get
    return app


def test_get_litestar_users_plugin_found() -> None:
    app = _make_app()
    plugin = get_litestar_users_plugin(app)
    assert plugin is not None


def test_get_litestar_users_plugin_missing_raises() -> None:
    app = _make_app(with_users_plugin=False)
    with pytest.raises(ImproperlyConfiguredException):
        get_litestar_users_plugin(app)


def test_get_sqlalchemy_plugin_found() -> None:
    app = _make_app()
    plugin = get_sqlalchemy_plugin(app)
    assert plugin is not None


def test_get_sqlalchemy_plugin_missing_raises() -> None:
    app = _make_app(with_sqlalchemy_plugin=False)
    with pytest.raises(ImproperlyConfiguredException):
        get_sqlalchemy_plugin(app)


@pytest.mark.asyncio
async def test_async_session_sequence_config_raises() -> None:
    """When SQLAlchemy config is a Sequence, async_session should raise."""

    app = _make_app()
    # Make the config a list (Sequence) to trigger the check
    sqlalchemy_plugin = get_sqlalchemy_plugin(app)
    sqlalchemy_plugin._config = [MagicMock(), MagicMock()]

    with pytest.raises(ImproperlyConfiguredException):
        async with async_session(app):
            pass


@pytest.mark.asyncio
async def test_async_session_sync_engine_raises() -> None:
    """When the engine is not async, async_session should raise."""

    app = _make_app()
    sqlalchemy_plugin = get_sqlalchemy_plugin(app)
    config = MagicMock()
    sync_engine = MagicMock(spec=Engine)  # not an AsyncEngine
    config.get_engine = MagicMock(return_value=sync_engine)
    sqlalchemy_plugin._config = config

    with pytest.raises(ImproperlyConfiguredException):
        async with async_session(app):
            pass


@pytest.mark.asyncio
async def test_async_session_yields_session() -> None:
    """Happy-path: async_session should yield a session."""

    app = _make_app()
    sqlalchemy_plugin = get_sqlalchemy_plugin(app)

    mock_session = MagicMock(spec=AsyncSession)
    mock_engine = MagicMock(spec=AsyncEngine)

    config = MagicMock()
    config.get_engine = MagicMock(return_value=mock_engine)
    sqlalchemy_plugin._config = config

    # Patch async_sessionmaker so we don't need a real engine
    mock_sessionmaker = MagicMock()
    mock_sessionmaker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_sessionmaker.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("litestar_users.utils.async_sessionmaker", return_value=mock_sessionmaker):
        async with async_session(app) as session:
            assert session is mock_session


def test_get_user_service_without_role_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """When config.role_model is None, role_repository should be None."""

    app = _make_app()
    session = MagicMock()

    users_plugin = get_litestar_users_plugin(app)
    config = users_plugin._config
    config.role_model = None
    config.user_auth_identifier = "email"
    config.secret = "secret-key-32-bytes-long-abcdefg"
    config.hash_schemes = ["argon2"]

    # Make user_repository_class return an AsyncMock repo
    fake_user_repo = AsyncMock()
    fake_user_repo.model_type = MagicMock()
    monkeypatch.setattr(config, "user_repository_class", MagicMock(return_value=fake_user_repo))

    # Make user_service_class capture its kwargs
    captured: dict = {}

    def _svc_factory(**kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock()

    monkeypatch.setattr(config, "user_service_class", _svc_factory)

    get_user_service(app, session)

    assert captured.get("role_repository") is None


def test_get_user_service_with_role_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """When config.role_model is set, role_repository should be provided."""

    app = _make_app()
    session = MagicMock()

    users_plugin = get_litestar_users_plugin(app)
    config = users_plugin._config
    config.role_model = MagicMock()
    config.user_auth_identifier = "email"
    config.secret = "secret-key-32-bytes-long-abcdefg"
    config.hash_schemes = ["argon2"]

    fake_user_repo = AsyncMock()
    fake_user_repo.model_type = MagicMock()
    monkeypatch.setattr(config, "user_repository_class", MagicMock(return_value=fake_user_repo))

    captured: dict = {}

    def _svc_factory(**kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock()

    monkeypatch.setattr(config, "user_service_class", _svc_factory)

    fake_role_repo = MagicMock()
    monkeypatch.setattr("litestar_users.utils.SQLAlchemyRoleRepository", MagicMock(return_value=fake_role_repo))

    get_user_service(app, session)

    assert captured.get("role_repository") is fake_role_repo
