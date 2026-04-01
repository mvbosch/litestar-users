# Data transfer objects

The user registration DTO can be an instance of either [DataclassDTO][litestar.dto.dataclass_dto.DataclassDTO], [MsgspecDTO][litestar.dto.msgspec_dto.MsgspecDTO] or [PydanticDTO][litestar.plugins.pydantic.PydanticDTO].

A few constraints are enforced by `LitestarUsersConfig` at startup:

- `user_read_dto` must not expose a field named `password` (plain-text password exposure).
- `user_registration_dto` must not include a field named `password_hash` (raw hash exposure).
- `user_update_dto` must be partial.
- `LitestarUsersConfig` automatically injects `rename_fields = {"password_hash": "password"}` into the update DTO, so that clients send `password` (not `password_hash`) when changing a user's password. Exclude `password_hash` from the update DTO only if you intentionally want to disable password changes via that endpoint.

!!! note
    Excluding `password_hash` from the **read** DTO is a security best practice — hashed passwords should never be returned to the client. This is not validated automatically.

## Example

```python
from dataclasses import dataclass

from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig
from litestar.dto import DataclassDTO

from .models import User


@dataclass
class UserRegistrationSchema:
    email: str
    password: str


class UserRegistrationDTO(DataclassDTO[UserRegistrationSchema]):
    """User registration DTO."""


class UserReadDTO(SQLAlchemyDTO[User]):
    # exclude password_hash so the hash is never sent to the client
    config = SQLAlchemyDTOConfig(exclude={"password_hash", "login_count"})


class UserUpdateDTO(SQLAlchemyDTO[User]):
    # password_hash is NOT excluded here: the framework renames it to `password`
    # in the API, allowing users to change their password via this endpoint.
    config = SQLAlchemyDTOConfig(exclude={"login_count"}, partial=True)
```

## Role DTOs

When using RBAC, role DTOs are passed directly to [`RoleManagementHandlerConfig`][litestar_users.config.RoleManagementHandlerConfig] rather than to `LitestarUsersConfig`:

```python
from advanced_alchemy.extensions.litestar.dto import SQLAlchemyDTO, SQLAlchemyDTOConfig

from .models import Role


class RoleCreateDTO(SQLAlchemyDTO[Role]):
    config = SQLAlchemyDTOConfig(exclude={"id"})


class RoleReadDTO(SQLAlchemyDTO[Role]):
    pass


class RoleUpdateDTO(SQLAlchemyDTO[Role]):
    config = SQLAlchemyDTOConfig(exclude={"id"}, partial=True)
```

These are then passed as required positional arguments when creating `RoleManagementHandlerConfig`. See [route handler configs](./4-route-handler-configs.md) for a complete example.
