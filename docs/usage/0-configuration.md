# Configuration

Litestar Users enables you to set up pre-configured authentication and user management route handlers in minutes.
The [LitestarUsers][litestar_users.main.LitestarUsers] accepts a config object in the form of [LitestarUsersConfig][litestar_users.config.LitestarUsersConfig]. The config requires [database models](./1-database-models.md), [DTOs](./2-data-transfer-objects.md), a [user service](./3-the-user-service.md) and one or more [route handler configs](./4-route-handler-configs.md).


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
from litestar.security.session_auth import SessionAuth

from litestar_users import LitestarUsersPlugin, LitestarUsersConfig
from litestar_users.adapter.sqlalchemy.mixins import SQLAlchemyUserMixin
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


class UserService(BaseUserService[User, Any]):  # type: ignore[type-var]
    async def post_registration_hook(self, user: User) -> None:
        print(f"User <{user.email}> has registered!")


sqlalchemy_config = SQLAlchemyAsyncConfig(
    connection_string=DATABASE_URL,
    session_dependency_key="session",
    before_send_handler="autocommit",
)

litestar_users = LitestarUsersPlugin(
    config=LitestarUsersConfig(
        auth_backend_class=SessionAuth,
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

!!! note
    Aside from the pre-configured public routes provided by Litestar-Users, *all* the routes on your application will require authentication unless specified otherwise in [LitestarUsersConfig.auth_exclude_paths][litestar_users.config.LitestarUsersConfig.auth_exclude_paths]

!!! note
    Litestar-Users requires the use of a corresponding `Litestar` [plugin](https://litestarproject.dev/lib/usage/plugins/index.html) for database management.
