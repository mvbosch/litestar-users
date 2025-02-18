# Database model mixins

::: litestar_users.adapter.sqlalchemy.mixins.SQLAlchemyUserMixin
    options:
        members:
            - email
            - password_hash
            - is_active
            - is_verified

::: litestar_users.adapter.sqlalchemy.mixins.SQLAlchemyRoleMixin
    options:
        members:
            - name
            - description
