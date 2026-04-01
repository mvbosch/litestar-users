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

See [Route Handler Configurations](./2-route-handler-configs.md) for the full reference.

## Anonymous access

::: litestar_users.anonymous.AnonymousUser

::: litestar_users.anonymous.no_validation
