from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions.http_exceptions import PermissionDeniedException

__all__ = ["roles_accepted", "roles_required"]


if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers import BaseRouteHandler
    from litestar.types import Guard


def roles_accepted(*roles: str) -> Guard:
    """Get a [Guard][litestar.types.Guard] callable and inject authorized role names.

    Args:
        roles: Iterable of authorized role names.

    Returns:
        Litestar [Guard][litestar.types.callable_types.Guard] callable
    """

    def roles_accepted_guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        """Authorize a request if any of the user's roles matches any of the supplied roles."""
        if any(role.name in roles for role in connection.user.roles):
            return
        raise PermissionDeniedException()

    return roles_accepted_guard


def roles_required(*roles: str) -> Guard:
    """Get a [Guard][litestar.types.Guard] callable and inject authorized role names.

    Args:
        roles: Iterable of authorized role names.
    """

    def roles_required_guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        """Authorize a request if the user's roles matches all of the supplied roles."""
        user_role_names = [role.name for role in connection.user.roles]
        if all(role in user_role_names for role in roles):
            return
        raise PermissionDeniedException()

    return roles_required_guard
