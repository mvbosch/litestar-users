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

* `forgot_password`: Inititiates the password reset flow. Always returns a HTTP 2XX status code.
* `reset_password`: Reset a user's password, given a valid reset token.

## [`RegisterHandlerConfig`][litestar_users.config.RegisterHandlerConfig]

Provides the following route handlers:

* `register` (aka signup). By default, newly registered users will need to verify their account before they can proceed to login. This behavior can be changed setting [`require_verification_on_registration`][litestar_users.config.LitestarUsersConfig.require_verification_on_registration] to `False` to disable verification for new users.

## [`RoleManagementHandlerConfig`][litestar_users.config.RoleManagementHandlerConfig]

Provides the following route handlers:

* `create_role`: Create a new role.
* `update_role`: Update a role.
* `delete_role`: Delete a role from the database.
* `assign_role`: Assign an existing role to an existing user.
* `revoke_role`: Revoke an existing role from an existing user.

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
