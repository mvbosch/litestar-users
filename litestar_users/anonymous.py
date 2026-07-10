from dataclasses import dataclass, field
from typing import Any

from litestar.connection import ASGIConnection
from litestar.types import Empty

__all__ = ["AnonymousUser"]


@dataclass
class AnonymousUser:
    """Sentinel representing an unauthenticated (anonymous) request.

    Route handlers that allow anonymous access can distinguish authenticated
    from anonymous callers via ``isinstance(request.user, AnonymousUser)``
    or by checking ``request.user.id is Empty``.
    """

    id: Any = field(default=Empty)
    is_active: bool = False
    is_verified: bool = False
    roles: list = field(default_factory=list)
    oauth_accounts: list = field(default_factory=list)


def _route_allows_anonymous(connection: ASGIConnection) -> bool:
    """Return ``True`` if the handler's ``current_user`` parameter accepts ``AnonymousUser``.

    Reads Litestar's already-parsed signature so no reflection is needed at
    request time. The handler must declare ``current_user`` as::

        current_user: SkipValidation[MyUser | AnonymousUser]
    """
    param = connection.route_handler.parsed_fn_signature.parameters.get("current_user")
    if param is None:
        return False
    if param.annotation is AnonymousUser:
        return True
    return any(inner.annotation is AnonymousUser for inner in param.inner_types)
