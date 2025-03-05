# Changelog

[v1.6.2]

- fix sqlalchemy session retrieval in `provide_user_service`

[v1.6.1]

- change password reset user lookups to be case-insensitive.
- fix user-defined session data being overridden on the login route handler.

[v1.6.0]

- add python 3.13 support.
- fix autocommit not adhering to config for some methods.
- add query options to user getter methods.
- add load options to authentication lookup.
- add list and count methods to `UserService`

[v1.5.0]

- add configurable user read DTOs per handler group.
- fix user defined exception handler override.

[v1.4.0]

- update user lookups to be case-insensitive.
- fix user password hash bug.

[v1.3.0]

- add JWT expiration time option.
- add auto_commit_transactions option.
- add verification toggle option.
- fix documentation.

[v1.2.3]

- add support for BigInt primary keys.

[v1.2.2]

- fix an instance check if not using `advanced_alchemy` model bases.

[v.1.2.1]

- add support for models with BigInt primary keys.
- change user management route path param names.

[v1.2.0]

- add experimental user relationship loader interface.

[v1.1.0]

- add `py.typed`.
- add authentication identifier customization.

[v1.0.0]

- add DTO validations on startup.
- add optional request context to various `BaserUserService` `pre-*` and `post-*` hooks.
- remove deprecated `LitestarUsersConfig.sqlalchemy_plugin_config`.

[v1.0.0rc3]

- add CLI.
- rename `LitestarUsers` class to `LitestarUsersPlugin`.

[v1.0.0rc2]

- add `LitestarUsersConfig.auth_backend_class` attribute.
- remove `LitestarUsersConfig.auth_backend` attribute.
- update role assignment/revocation route handlers to use HTTP PUT.

[v1.0.0rc1]

- update the package to work with `litestar` v2.1.1
- drop `pydantic` dependency.

[v0.8.0]

- fix `retrieve_user_handler` to use the same db session used in dependency injection.

[v0.7.1]

- fix unset default argument on `BaseUserService`.
- fix unset `UserCreateDTO` fields to be excluded from user creation.

[v0.7.0]

- update (harden) authentication algorithm.
- remove built-in `OpenAPIConfig` instance.

[v0.6.0]

- add `argon2-cffi` dependency.
- default password hashing scheme to `argon2`.

[0.5.0]

- add defaults to `StarliteUsersConfig` options.
- add option to subclass the user repository.
- fix documentation links.
- rework how routes are excluded from authentication.

[0.4.0]

- unify `BaseUserService` and `BaseUserRoleService` et al.
- add configuration options to `StarliteUsersConfig`.
- add `hash_schemes` configuration to `PasswordManager`
- remove configuration class variables from `BaseUserService`.
- remove `UserRoleAssociationMixin`.
- remove `SQLAlchemyUserRoleMixin`.
- remove `__tablename__` declarations from SQLAlchemy mixins.

[0.3.3]

- fix session login response serialization issue.

[0.3.2]

- fix verification issue.

[0.3.1]

- replace broken SQLAlchemy forward refs.

[0.3.0]

- add `BaseUserRoleService`
- add `BaseUserRoleReadDTO`
- add `SQLAlchemyUserRoleRepository`
- add `SQLAlchemyUserRolesMixin`
- remove `role` based methods from `BaseUserService`
- remove `role` based methods from `SQLAlchemyUserRepository`
- remove `roles` attribute from `BaseUserReadDTO`
- remove `roles` attribute from `SQLAlchemyUserMixin`
- update `get_service` dependency function.
- update `retrieve_user_handler` helpers.
- update examples.

[0.2.0]

- fix static type and linting errors.
- fix documentation issues.
- update route handler authorization guards to be generic.

[0.1.0]

- initial release.
