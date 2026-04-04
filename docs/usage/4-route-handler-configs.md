# Route handler configs

Simply adding any of the configuration classes below to `LitestarUsersConfig` will register the relevant route handlers on your Litestar application. All route paths are configurable via these interfaces:


## [`AuthHandlerConfig`][litestar_users.config.AuthHandlerConfig]

Provides the following route handlers:

* `login`: Allows users to authenticate.
* `logout`: Allows authenticated users to logout. Not available when the authentication backend is JWT based.

## [`CurrentUserHandlerConfig`][litestar_users.config.CurrentUserHandlerConfig]

Provides the following route handlers:

* `get_current_user`: Get info on the currently authenticated user.
* `update_current_user`: Update the currently authenticated user's info.

## [`PasswordResetHandlerConfig`][litestar_users.config.PasswordResetHandlerConfig]

Provides the following route handlers:

* `forgot_password`: Initiates the password reset flow. Always returns a HTTP 2XX status code.
* `reset_password`: Reset a user's password, given a valid reset token.

## [`RegisterHandlerConfig`][litestar_users.config.RegisterHandlerConfig]

Provides the following route handlers:

* `register` (aka signup). By default, newly registered users will need to verify their account before they can proceed to login. This behavior can be changed by setting [`require_verification_on_registration`][litestar_users.config.LitestarUsersConfig.require_verification_on_registration] to `False`.

## [`RoleManagementHandlerConfig`][litestar_users.config.RoleManagementHandlerConfig]

Provides the following route handlers:

* `create_role`: Create a new role.
* `update_role`: Update a role.
* `delete_role`: Delete a role from the database.
* `assign_role`: Assign an existing role to an existing user.
* `revoke_role`: Revoke an existing role from an existing user.

`RoleManagementHandlerConfig` requires three positional DTO arguments:

```python
from litestar_users.config import RoleManagementHandlerConfig
from litestar_users.guards import roles_accepted


# Stub definitions — see Data transfer objects -> Role DTOs for the full implementation
class RoleCreateDTO: ...  # noqa: E701


class RoleReadDTO: ...  # noqa: E701


class RoleUpdateDTO: ...  # noqa: E701


role_management_handler_config = RoleManagementHandlerConfig(
    role_create_dto=RoleCreateDTO,
    role_read_dto=RoleReadDTO,
    role_update_dto=RoleUpdateDTO,
    guards=[roles_accepted("administrator")],
)
```

See [Data transfer objects](./2-data-transfer-objects.md) for how to define the role DTOs.

## [`UserManagementHandlerConfig`][litestar_users.config.UserManagementHandlerConfig]

Provides the following route handlers:

* `get_user`: Get user info.
* `update_user`: Update a user's info.
* `delete_user`: Delete a user from the database.

## [`VerificationHandlerConfig`][litestar_users.config.VerificationHandlerConfig]

Provides the following route handlers:

* `verify`: Update a user's `is_verified` status to `True`, given a valid token.


## [`OAuth2HandlerConfig`][litestar_users.config.OAuth2HandlerConfig]

Provides the following route handlers:

* `authorize`: Redirects the user to the OAuth2 provider's authorization page.
* `callback`: Handles the OAuth2 provider's callback.

## Eager-loading relationships via `user_load_options`

Certain route handlers registered by litestar-users respect an `opt` key called `user_load_options`. When present, its value is passed directly as the `load` argument to the underlying repository query, allowing you to eagerly load SQLAlchemy relationships for that specific handler.

This is useful whenever your response DTO or schema requires related objects to be present - for example, including role information on the login response, or loading a user's orders after OAuth2 sign-in.

`user_load_options` is honoured in three places:

* **`BaseUserService.authenticate`** - runs the relationship load when resolving the user during login, so the returned user already has the requested relations populated.
* **`BaseUserService.get_by_oauth_account`** - runs the relationship load during the OAuth2 callback flow.
* **JWT / session authentication middleware** - runs the relationship load when hydrating the request's authenticated user on every subsequent request.

```python
from litestar_users.config import AuthHandlerConfig
from sqlalchemy.orm import selectinload

from local.models import User


# Eager-load `User.orders` on the login response,
# e.g. to satisfy a response DTO that includes an `orders` field.
auth_handler_config = AuthHandlerConfig(
    opt={"user_load_options": [selectinload(User.orders)]},
)
```

!!!note
    The value must be a sequence of [`sqlalchemy.orm.Load`](https://docs.sqlalchemy.org/en/20/orm/queryguide/api.html#sqlalchemy.orm.Load) instances (e.g. `selectinload`, `joinedload`, `subqueryload`). Passing any other type raises a `ValueError` at authentication time.
