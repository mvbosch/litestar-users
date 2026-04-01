# Configuration

Litestar Users enables you to set up pre-configured authentication and user management route handlers in minutes.
The `LitestarUsersPlugin` accepts a config object in the form of [LitestarUsersConfig][litestar_users.config.LitestarUsersConfig]. The config requires [database models](./1-database-models.md), [DTOs](./2-data-transfer-objects.md), a [user service](./3-the-user-service.md) and one or more [route handler configs](./4-route-handler-configs.md).


## Minimal example

A minimal example with registration, verification and login facilities:

```python
from dataclasses import dataclass
from typing import Any

import uvicorn
from advanced_alchemy.base import UUIDBase
from litestar import Litestar
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from advanced_alchemy.extensions.litestar.plugins import (
    SQLAlchemyAsyncConfig,
    SQLAlchemyInitPlugin,
)
from litestar.dto import DataclassDTO
from litestar.middleware.session.server_side import ServerSideSessionConfig

from litestar_users import LitestarUsersPlugin, LitestarUsersConfig
from litestar_users.mixins import SQLAlchemyUserMixin
from litestar_users.config import (
    AuthHandlerConfig,
    RegisterHandlerConfig,
    VerificationHandlerConfig,
)
from litestar_users.service import BaseUserService

ENCODING_SECRET = "1234567890abcdef"  # noqa: S105
DATABASE_URL = "sqlite+aiosqlite:///"


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""


@dataclass
class UserRegistrationSchema:
    email: str
    password: str


class UserRegistrationDTO(DataclassDTO[UserRegistrationSchema]):
    """User registration DTO."""


class UserReadDTO(SQLAlchemyDTO[User]):
    config = SQLAlchemyDTOConfig(exclude={"password_hash"})


class UserUpdateDTO(SQLAlchemyDTO[User]):
    config = SQLAlchemyDTOConfig(exclude={"password_hash"}, partial=True)


class UserService(BaseUserService[User, Any, Any]):  # type: ignore[type-var]
    async def post_registration_hook(self, user: User, request: Any = None) -> None:
        print(f"User <{user.email}> has registered!")


sqlalchemy_config = SQLAlchemyAsyncConfig(
    connection_string=DATABASE_URL,
    session_dependency_key="session",
    before_send_handler="autocommit",
)

litestar_users = LitestarUsersPlugin(
    config=LitestarUsersConfig(
        auth_config=ServerSideSessionConfig(),
        secret=ENCODING_SECRET,
        user_model=User,  # pyright: ignore
        user_read_dto=UserReadDTO,
        user_registration_dto=UserRegistrationDTO,
        user_update_dto=UserUpdateDTO,
        user_service_class=UserService,  # pyright: ignore
        auth_handler_config=AuthHandlerConfig(),
        register_handler_config=RegisterHandlerConfig(),
        verification_handler_config=VerificationHandlerConfig(),
    )
)

app = Litestar(
    plugins=[SQLAlchemyInitPlugin(config=sqlalchemy_config), litestar_users],
    route_handlers=[],
)

if __name__ == "__main__":
    uvicorn.run(app="basic:app", reload=True)
```

## Authentication backends

The `auth_config` parameter accepts one of:

| Config class | Backend |
| --- | --- |
| `ServerSideSessionConfig` / `CookieBackendConfig` | Session-based (cookie) |
| [`JWTAuthConfig`][litestar_users.config.JWTAuthConfig] | Stateless JWT bearer token |
| [`JWTCookieAuthConfig`][litestar_users.config.JWTCookieAuthConfig] | JWT stored in an `HttpOnly` cookie |

```python
from litestar_users.config import JWTAuthConfig

# Pass JWTAuthConfig() as auth_config; all other LitestarUsersConfig fields are unchanged
auth_config = JWTAuthConfig()
```

!!! warning
    Set `SQLAlchemyAsyncConfig.before_send_handler` to `"autocommit"` to ensure database transactions are committed atomically at the end of the request/response lifecycle. If an error is raised the transaction is rolled back automatically.

    Alternatively, you may set [LitestarUsersConfig.auto_commit_transactions][litestar_users.config.LitestarUsersConfig.auto_commit_transactions] to `True`, but this commits immediately after each service call (e.g. `UserService.register`). If a subsequent `post_registration_hook` raises an exception the user will have already been persisted, resulting in a confusing duplicate-registration error on the next attempt.

!!! note
    Aside from the pre-configured public routes provided by Litestar-Users, *all* routes on your application require authentication unless excluded via [LitestarUsersConfig.auth_exclude_paths][litestar_users.config.LitestarUsersConfig.auth_exclude_paths].

!!! note
    Litestar-Users requires the use of a corresponding `Litestar` [plugin](https://docs.litestar.dev/latest/usage/plugins/index.html) for database management.

## Anonymous users

By default every route (except those in `auth_exclude_paths`) requires a valid session or token. If you need a route to be accessible to unauthenticated callers without excluding it globally, Litestar-Users provides [`AnonymousUser`][litestar_users.AnonymousUser] and [`no_validation`][litestar_users.no_validation].

Declare `current_user` as a union that includes `AnonymousUser` on any handler that should accept unauthenticated requests. The middleware will set `request.user` to an `AnonymousUser` instance instead of raising a 401, and you can distinguish the two cases with `isinstance`:

```python
from typing import Annotated

from litestar import get
from litestar_users import AnonymousUser, no_validation

from .models import User


@get("/feed")
async def feed(
    current_user: Annotated[User | AnonymousUser, no_validation],
) -> list[str]:
    if isinstance(current_user, AnonymousUser):
        return ["public item 1", "public item 2"]
    return [
        "public item 1",
        "public item 2",
        f"personalized item for {current_user.email}",
    ]
```

`AnonymousUser` exposes the same base attributes as a real user (`id`, `is_active`, `is_verified`, `roles`, `oauth_accounts`) with safe sentinel defaults, so code that inspects those fields does not need special-casing.

!!! note
    The `no_validation` annotation is required because msgspec cannot coerce a union of two custom types. Without it Litestar will raise a validation error when it tries to deserialise the dependency. It is simply `Dependency(skip_validation=True)` — you can use that directly if you prefer not to import `no_validation`.
