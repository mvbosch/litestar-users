# Database Model Mixins

::: litestar_users.mixins.SQLAlchemyUserMixin
    options:
        members:
            - email
            - password_hash
            - is_active
            - is_verified

::: litestar_users.mixins.SQLAlchemyRoleMixin
    options:
        members:
            - name
            - description

::: litestar_users.mixins.SQLAlchemyOAuthAccountMixin
    options:
        members:
            - user_id
            - oauth_name
            - access_token
            - account_id
            - account_email
            - expires_at
            - refresh_token
