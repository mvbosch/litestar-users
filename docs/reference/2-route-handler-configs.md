# Route Handler Configurations

::: litestar_users.config.AuthHandlerConfig
    options:
        members:
            - login_path
            - logout_path
            - tags

::: litestar_users.config.CurrentUserHandlerConfig
    options:
        members:
            - path
            - tags

::: litestar_users.config.PasswordResetHandlerConfig
    options:
        members:
            - forgot_path
            - reset_path
            - tags

::: litestar_users.config.RegisterHandlerConfig
    options:
        members:
            - path
            - tags

::: litestar_users.config.RoleManagementHandlerConfig
    options:
        members:
            - path_prefix
            - assign_role_path
            - revoke_role_path
            - guards
            - tags

::: litestar_users.config.UserManagementHandlerConfig
    options:
        members:
            - path_prefix
            - guards
            - tags

::: litestar_users.config.VerificationHandlerConfig
    options:
        members:
            - path
            - tags

::: litestar_users.config.OAuth2HandlerConfig
    options:
        members:
            - oauth_client
            - state_secret
            - path
            - tags
            - redirect_url
            - associate_by_email
            - is_verified_by_default
