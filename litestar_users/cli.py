from __future__ import annotations

import sys
from typing import TYPE_CHECKING, cast

import anyio
from advanced_alchemy.exceptions import IntegrityError, NotFoundError
from click import echo, group, option, prompt
from litestar.cli._utils import LitestarGroup

from litestar_users.utils import async_session, get_litestar_users_plugin, get_user_service

if TYPE_CHECKING:
    from litestar import Litestar


@group(cls=LitestarGroup, name="users")
def user_management_group() -> None:
    """Manage users."""


@user_management_group.command(
    name="create-user",
    help="Create a new user in the database.",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@option("--email", help="The user's email address.")
@option("--password", help="The new user's login password.")
@option("--is-active", is_flag=True, default=False, type=bool, help="Set the user as active.")
@option("--is-verified", is_flag=True, default=False, type=bool, help="Set the user as verified.")
@option("--id", "user_id", help="Set the user ID.")
@option(
    "--bool-attrs", "-b", "booleans", multiple=True, help="Set one or more custom boolean attribute key-value pairs."
)
@option("--float-attrs", "-f", "floats", multiple=True, help="Set one or more custom float attribute key-value pairs.")
@option(
    "--int-attrs", "-i", "integers", multiple=True, help="Set one or more custom integer attribute key-value pairs."
)
@option("--str-attrs", "-s", "strings", multiple=True, help="Set one or more custom string attribute key-value pairs.")
def create_user(
    app: Litestar,
    email: str,
    password: str,
    is_active: bool,
    is_verified: bool,
    user_id: str | None,
    booleans: tuple[str],
    integers: tuple[str],
    floats: tuple[str],
    strings: tuple[str],
) -> None:
    """Create a new user in the database."""
    kwargs: dict[str, str | int | float | bool] = {}
    try:
        kwargs.update(
            {
                key: value.lower() in ("1", "true", "t", "yes", "y")
                for arg in booleans
                for key, value in [arg.split("=")]
            }
        )
        kwargs.update({key: int(value) for arg in integers for key, value in [arg.split("=")]})
        kwargs.update({key: float(value) for arg in floats for key, value in [arg.split("=")]})
        kwargs.update({key: value for arg in strings for key, value in [arg.split("=")]})
    except ValueError as e:
        echo(f"Error: {e}", err=True)
        sys.exit(1)
    if user_id:
        kwargs["id"] = int(user_id) if user_id.isnumeric() else user_id

    litestar_users_config = get_litestar_users_plugin(app)._config

    email = email or prompt("User email")
    password = password or prompt("User password", hide_input=True, confirmation_prompt=True)

    async def _create_user() -> None:
        async with async_session(app) as session:
            user_service = get_user_service(app, session)
            password_hash = user_service.password_manager.hash(password)
            try:
                user = await user_service.add_user(
                    user=litestar_users_config.user_model(email=email, password_hash=password_hash, **kwargs),
                    activate=is_active,
                    verify=is_verified,
                )
                await session.commit()
                echo(f"User {user.id} created successfully.")
            except IntegrityError as e:
                # could be caught IntegrityError or unique collision
                msg = e.__cause__ if e.__cause__ else e
                echo(f"Error: {msg}", err=True)
                sys.exit(1)
            except TypeError as e:
                echo(f"Error: {e}", err=True)
                sys.exit(1)

    anyio.run(_create_user)


@user_management_group.command(name="create-role", help="Create a new role in the database.")
@option("--name")
@option("--description")
def create_role(app: Litestar, name: str | None, description: str | None) -> None:
    """Create a new role in the database."""

    litestar_users_config = get_litestar_users_plugin(app)._config

    name = name or prompt("Role name")

    async def _create_role() -> None:
        async with async_session(app) as session:
            user_service = get_user_service(app, session)
            if litestar_users_config.role_model is None:
                echo("Role model is not defined")
                sys.exit(1)
            try:
                role = await user_service.add_role(litestar_users_config.role_model(name=name, description=description))
                await session.commit()
                echo(f"Role {role.id} created successfully.")
            except IntegrityError as e:
                # could be caught IntegrityError or unique collision
                msg = e.__cause__ if e.__cause__ else e
                echo(f"Error: {msg}", err=True)
                sys.exit(1)

    anyio.run(_create_role)


@user_management_group.command(name="assign-role", help="Assign a role to a user.")
@option("--email")
@option("--role")
def assign_role(
    app: Litestar,
    email: str | None,
    role: str | None,
) -> None:
    """Assign a role to a user."""

    litestar_users_config = get_litestar_users_plugin(app)._config
    if litestar_users_config.role_model is None:
        echo("Role model is not defined")
        sys.exit(1)

    email = email or prompt("User email")
    role = role or cast("str", prompt("Role", type=str))

    async def _assign_role() -> None:
        async with async_session(app) as session:
            user_service = get_user_service(app, session)
            try:
                user = await user_service.get_user_by(email=email)
                if user is None:
                    raise NotFoundError()
            except NotFoundError:
                echo("User not found", err=True)
                sys.exit(1)
            try:
                role_db = await user_service.get_role_by_name(role)
            except NotFoundError:
                echo("Role not found", err=True)
                sys.exit(1)
            await user_service.assign_role(user.id, role_db.id)
        echo(f"Role {role} assigned to user {email} successfully.")

    anyio.run(_assign_role)
