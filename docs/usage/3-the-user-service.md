# The user service class

The [`UserService`][litestar_users.service.BaseUserService] class is the interface for all user and role related operations. It is meant to be subclassed in order to configure how to deliver your application's verification and password recovery tokens.

## Suggested method overrides

* [`send_verification_token`][litestar_users.service.BaseUserService.send_verification_token]
* [`send_password_reset_token`][litestar_users.service.BaseUserService.send_password_reset_token]

!!!note
    The method [`send_verification_token`][litestar_users.service.BaseUserService.send_verification_token] is used only when [`require_verification_on_registration`][litestar_users.config.LitestarUsersConfig.require_verification_on_registration] is set to `True` (the default value). If no verification is required and [`require_verification_on_registration`][litestar_users.config.LitestarUsersConfig.require_verification_on_registration] is set to `False`, the method will not be invoked.

### Example

```python
from typing import Any

from litestar_users.service import BaseUserService

from local.models import User
from local.services import EmailService


class UserService(BaseUserService[User, Any, Any]):
    async def send_verification_token(self, user: User, token: str) -> None:
        email_service = EmailService()
        email_service.send(
            email=user.email,
            message=f"Welcome! Your verification link is https://mysite.com/verify?token={token}",
        )
```

## Optional method overrides

### [`pre_login_hook`][litestar_users.service.BaseUserService.pre_login_hook]

Executes custom asynchronous code *before* the authentication process proceeds.
If you have business requirements to halt the authentication process for any reason, this would be a good place to do so. Simply raise an exception (ideally you'd map this to a HTTP 4xx response)

### [`post_login_hook`][litestar_users.service.BaseUserService.post_login_hook]

Executes custom asynchronous code *after* the authentication process has succeeded.
This is the ideal location to update for example a user's login count or last login IP address.

### [`pre_registration_hook`][litestar_users.service.BaseUserService.pre_registration_hook]

Executes custom asynchronous code *before* the user registration process proceeds.
If you have business requirements to halt the registration process for any reason, this would be a good place to do so. Simply raise an exception (ideally you'd map this to a HTTP 4xx response)

### [`post_registration_hook`][litestar_users.service.BaseUserService.post_registration_hook]

Executes custom asynchronous code *after* the registration process has succeeded.
This could be used to send users a "welcoming email" describing the application verification process, etc.

### [`post_verification_hook`][litestar_users.service.BaseUserService.post_verification_hook]

Executes custom asynchronous code *after* a user has successfully verified their account.
An example use is updating external sources with active user metrics, etc.
