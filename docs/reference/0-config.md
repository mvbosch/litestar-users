# Litestar-Users Configuration

::: litestar_users.config.LitestarUsersConfig
    options:
        members:
            - auth_config
            - auth_exclude_paths
            - auto_commit_transactions
            - secret
            - hash_schemes
            - user_model
            - user_registration_dto
            - user_read_dto
            - user_update_dto
            - oauth_account_model
            - role_model
            - user_auth_identifier
            - user_service_class
            - require_verification_on_registration
            - auth_handler_config
            - current_user_handler_config
            - password_reset_handler_config
            - register_handler_config
            - oauth2_handler_config
            - oauth2_associate_handler_config
            - role_management_handler_config
            - user_management_handler_config
            - verification_handler_config

## Authentication backend configs

::: litestar_users.config.JWTAuthConfig
    options:
        members:
            - algorithm
            - auth_header
            - token_expiration

::: litestar_users.config.JWTCookieAuthConfig
    options:
        members:
            - algorithm
            - auth_header
            - token_expiration
            - cookie_key
            - cookie_path
            - cookie_secure
            - cookie_samesite
            - cookie_domain

## Route handler configs

::: litestar_users.config.AuthHandlerConfig
    options:
        members:
            - login_path
            - logout_path
            - opt
            - tags
            - user_read_dto

::: litestar_users.config.CurrentUserHandlerConfig
    options:
        members:
            - path
            - opt
            - tags
            - user_read_dto

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
            - role_create_dto
            - role_read_dto
            - role_update_dto
            - path_prefix
            - assign_role_path
            - revoke_role_path
            - guards
            - opt
            - tags

::: litestar_users.config.UserManagementHandlerConfig
    options:
        members:
            - path_prefix
            - guards
            - opt
            - tags
            - user_read_dto

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
            - redirect_url
            - associate_by_email
            - is_verified_by_default
            - guards
            - tags
            - user_read_dto
