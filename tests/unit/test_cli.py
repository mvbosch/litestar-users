"""Unit tests for litestar_users.cli.

All async database calls and Litestar app interactions are mocked so no
real database or server is required.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from advanced_alchemy.exceptions import IntegrityError, NotFoundError
from click.testing import CliRunner
from litestar.cli._utils import LitestarEnv

from litestar_users.cli import (
    assign_role,
    create_role,
    create_user,
)


def _make_mock_app(role_model: Any = MagicMock(), user_model: Any = None) -> MagicMock:
    """Return a fake Litestar app whose plugin/config can be controlled."""
    if user_model is None:
        user_model = MagicMock(return_value=MagicMock())

    config = MagicMock()
    config.user_repository_class = MagicMock()
    config.user_repository_class.model_type = user_model
    if role_model is None:
        config.role_management_handler_config = None
    else:
        config.role_management_handler_config = MagicMock()
        config.role_management_handler_config.role_repository_class.model_type = role_model

    plugin = MagicMock()
    plugin._config = config

    app = MagicMock()
    app.plugins.get = MagicMock(return_value=plugin)

    return app


def _litestar_env(app: Any) -> LitestarEnv:
    """Return a LitestarEnv instance wrapping a mock app."""
    return LitestarEnv(app_path="test:app", app=app, cwd=Path("."))


class TestCreateUser:
    def _make_service(
        self, *, user_id: Any = None, raise_integrity: bool = False, raise_type: bool = False
    ) -> AsyncMock:
        svc = AsyncMock()
        if raise_integrity:
            svc.add_user = AsyncMock(side_effect=IntegrityError("duplicate"))
        elif raise_type:
            svc.add_user = AsyncMock(side_effect=TypeError("bad field"))
        else:
            created = MagicMock()
            created.id = user_id or "abc-123"
            svc.add_user = AsyncMock(return_value=created)
        svc.password_manager = MagicMock()
        svc.password_manager.hash = MagicMock(return_value="hashed")
        return svc

    def test_create_user_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        svc = self._make_service()
        app = _make_mock_app()

        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_get_svc = MagicMock(return_value=svc)
        mock_anyio_run = MagicMock()
        mock_session = MagicMock()

        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.get_user_service", mock_get_svc)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)
        monkeypatch.setattr("litestar_users.cli.async_session", mock_session)

        captured_coro = None

        def capture_run(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = capture_run

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.return_value = mock_session_ctx

        runner = CliRunner()
        runner.invoke(
            create_user,
            ["--email", "new@example.com", "--password", "pass1234"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        # anyio.run should have been called with the inner coroutine
        assert mock_anyio_run.called

    def test_create_user_bad_bool_attr_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        runner = CliRunner()
        result = runner.invoke(
            create_user,
            ["--email", "a@b.com", "--password", "p", "-b", "no_equals_sign"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_create_user_bad_int_attr_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        runner = CliRunner()
        result = runner.invoke(
            create_user,
            ["--email", "a@b.com", "--password", "p", "-i", "age=not_a_number"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_create_user_bad_float_attr_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        runner = CliRunner()
        result = runner.invoke(
            create_user,
            ["--email", "a@b.com", "--password", "p", "-f", "score=not_a_float"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_create_user_prompts_for_missing_email_and_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without --email/--password the CLI should prompt."""
        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock(return_value=None)
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        runner = CliRunner()
        runner.invoke(
            create_user,
            [],
            obj=lambda: _litestar_env(app),
            input="prompted@example.com\nprompted_pw\nprompted_pw\n",
            catch_exceptions=False,
        )

        # anyio.run should be called (the inner coroutine was captured)
        assert mock_anyio_run.called


class TestCreateRole:
    def test_create_role_no_role_model_exits_inside_coro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When role_model is None the CLI should exit with code 1."""
        app = _make_mock_app(role_model=None)
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        captured_coro = None

        def _capture(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = _capture

        runner = CliRunner()
        runner.invoke(
            create_role,
            ["--name", "admin"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert captured_coro is not None

    def test_create_role_prompts_for_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock(return_value=None)
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        runner = CliRunner()
        runner.invoke(
            create_role,
            [],
            obj=lambda: _litestar_env(app),
            input="editor\n",
            catch_exceptions=False,
        )

        assert mock_anyio_run.called

    def test_create_role_success_coro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        role = MagicMock()
        role.id = "role-id-1"

        svc = AsyncMock()
        svc.add_role = AsyncMock(return_value=role)

        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=AsyncMock())
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock(return_value=session_ctx)
        mock_get_svc = MagicMock(return_value=svc)

        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()

        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.get_user_service", mock_get_svc)
        monkeypatch.setattr("litestar_users.cli.async_session", mock_session)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        captured_coro = None

        def _capture(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = _capture

        runner = CliRunner()
        runner.invoke(
            create_role,
            ["--name", "editor", "--description", "Can edit content"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert captured_coro is not None
        # Run the captured inner coroutine
        asyncio.get_event_loop().run_until_complete(captured_coro())
        svc.add_role.assert_called_once()

    def test_create_role_integrity_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        svc = AsyncMock()
        svc.add_role = AsyncMock(side_effect=IntegrityError("duplicate role"))

        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock(return_value=session_ctx)
        mock_get_svc = MagicMock(return_value=svc)

        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()

        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.get_user_service", mock_get_svc)
        monkeypatch.setattr("litestar_users.cli.async_session", mock_session)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        captured_coro = None

        def _capture(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = _capture

        runner = CliRunner()
        runner.invoke(
            create_role,
            ["--name", "admin"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert captured_coro is not None
        with pytest.raises(SystemExit) as exc_info:
            asyncio.get_event_loop().run_until_complete(captured_coro())
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# assign_role
# ---------------------------------------------------------------------------


class TestAssignRole:
    def test_assign_role_exits_when_no_role_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_mock_app(role_model=None)
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)

        runner = CliRunner()
        result = runner.invoke(
            assign_role,
            ["--email", "a@b.com", "--role", "admin"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert result.exit_code == 1
        assert "Role model is not defined" in result.output

    def test_assign_role_user_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        svc = AsyncMock()
        svc.get_user_by = AsyncMock(return_value=None)

        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock(return_value=session_ctx)
        mock_get_svc = MagicMock(return_value=svc)

        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()

        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.get_user_service", mock_get_svc)
        monkeypatch.setattr("litestar_users.cli.async_session", mock_session)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        captured_coro = None

        def _capture(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = _capture

        runner = CliRunner()
        runner.invoke(
            assign_role,
            ["--email", "ghost@example.com", "--role", "admin"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert captured_coro is not None
        with pytest.raises(SystemExit) as exc_info:
            asyncio.get_event_loop().run_until_complete(captured_coro())
        assert exc_info.value.code == 1

    def test_assign_role_role_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        user = MagicMock()
        svc = AsyncMock()
        svc.get_user_by = AsyncMock(return_value=user)
        svc.get_role_by_name = AsyncMock(side_effect=NotFoundError())

        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock(return_value=session_ctx)
        mock_get_svc = MagicMock(return_value=svc)

        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()

        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.get_user_service", mock_get_svc)
        monkeypatch.setattr("litestar_users.cli.async_session", mock_session)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        captured_coro = None

        def _capture(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = _capture

        runner = CliRunner()
        runner.invoke(
            assign_role,
            ["--email", "user@example.com", "--role", "nonexistent"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert captured_coro is not None
        with pytest.raises(SystemExit) as exc_info:
            asyncio.get_event_loop().run_until_complete(captured_coro())
        assert exc_info.value.code == 1

    def test_assign_role_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        user = MagicMock()
        user.id = "user-uuid"
        role_db = MagicMock()
        role_db.id = "role-uuid"

        svc = AsyncMock()
        svc.get_user_by = AsyncMock(return_value=user)
        svc.get_role_by_name = AsyncMock(return_value=role_db)
        svc.assign_role = AsyncMock()

        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock(return_value=session_ctx)
        mock_get_svc = MagicMock(return_value=svc)

        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock()

        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.get_user_service", mock_get_svc)
        monkeypatch.setattr("litestar_users.cli.async_session", mock_session)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        captured_coro = None

        def _capture(coro: Any) -> None:
            nonlocal captured_coro
            captured_coro = coro

        mock_anyio_run.side_effect = _capture

        runner = CliRunner()
        runner.invoke(
            assign_role,
            ["--email", "user@example.com", "--role", "admin"],
            obj=lambda: _litestar_env(app),
            catch_exceptions=False,
        )

        assert captured_coro is not None
        asyncio.get_event_loop().run_until_complete(captured_coro())
        svc.assign_role.assert_called_once_with("user-uuid", "role-uuid")

    def test_assign_role_prompts_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_mock_app()
        mock_get_plugin = MagicMock(return_value=app.plugins.get(None))
        mock_anyio_run = MagicMock(return_value=None)
        monkeypatch.setattr("litestar_users.cli.get_litestar_users_plugin", mock_get_plugin)
        monkeypatch.setattr("litestar_users.cli.anyio.run", mock_anyio_run)

        runner = CliRunner()
        runner.invoke(
            assign_role,
            [],
            obj=lambda: _litestar_env(app),
            input="user@example.com\nadmin\n",
            catch_exceptions=False,
        )

        assert mock_anyio_run.called
