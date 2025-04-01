# User Service

::: litestar_users.service.BaseUserService
    options:
        members:
            - __init__
            - add_user
            - register
            - get_user
            - get_user_by
            - update_user
            - delete_user
            - authenticate
            - generate_token
            - initiate_verification
            - send_verification_token
            - verify
            - initiate_password_reset
            - send_password_reset_token
            - reset_password
            - pre_login_hook
            - post_login_hook
            - pre_registration_hook
            - post_registration_hook
            - post_verification_hook
            - get_role
            - get_role_by_name
            - add_role
            - update_role
            - delete_role
            - assign_role
            - revoke_role
            - get_by_oauth_account
            - oauth2_authorize
            - oauth2_callback
