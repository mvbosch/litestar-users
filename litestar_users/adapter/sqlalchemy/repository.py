from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generic

from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from litestar.exceptions import ImproperlyConfiguredException

from litestar_users.adapter.sqlalchemy.protocols import SQLAOAuthAccountT, SQLARoleT, SQLAUserT

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["SQLAlchemyRoleRepository", "SQLAlchemyUserRepository"]


class SQLAlchemyUserRepository(SQLAlchemyAsyncRepository[SQLAUserT], Generic[SQLAUserT]):
    """SQLAlchemy implementation of user persistence layer."""

    def __init__(self, session: AsyncSession, model_type: type[SQLAUserT], **kwargs: Any) -> None:
        """Repository for users.

        Args:
            session: Session managing the unit-of-work for the operation.
            model_type: A subclass of `SQLAlchemyUserModel`.
            kwargs: Additional keyword arguments to pass to superclass.
        """
        self.model_type = model_type
        super().__init__(session=session, **kwargs)

    async def _update(self, user: SQLAUserT, data: dict[str, Any]) -> SQLAUserT:
        for key, value in data.items():
            setattr(user, key, value)

        if self.auto_commit:
            await self.session.commit()

        return user


class SQLAlchemyOAuthAccountRepository(
    SQLAlchemyAsyncRepository[SQLAOAuthAccountT], Generic[SQLAOAuthAccountT, SQLAUserT]
):
    """SQLAlchemy implementation of OAuth account persistence layer."""

    def __init__(self, session: AsyncSession, model_type: type[SQLAOAuthAccountT], **kwargs: Any) -> None:
        """Repository for OAuth accounts.

        Args:
            session: Session managing the unit-of-work for the operation.
            model_type: A subclass of `SQLAlchemyOAuthAccountModel`.
            kwargs: Additional keyword arguments to pass to superclass.
        """
        self.model_type = model_type
        super().__init__(session=session, **kwargs)

    async def add_oauth_account(self, user: SQLAUserT, data: dict[str, Any]) -> SQLAUserT:
        """Add an OAuth account to a user.

        Args:
            user: The user to add the OAuth account to.
            data: The data to add to the OAuth account.
        """
        if not hasattr(user, "oauth_accounts"):
            raise ImproperlyConfiguredException("User.oauth_accounts is not set")

        user.oauth_accounts.append(self.model_type(**data))  # pyright: ignore

        if self.auto_commit:
            await self.session.commit()

        return user

    async def update_oauth_account(
        self, user: SQLAUserT, oauth_account: SQLAOAuthAccountT, data: dict[str, Any]
    ) -> SQLAUserT:
        """Update an OAuth account for a user.

        Args:
            user: The user to update the OAuth account for.
            oauth_account: The OAuth account to update.
            data: The data to update the OAuth account with.
        """
        if not hasattr(user, "oauth_accounts"):
            raise ImproperlyConfiguredException("User.oauth_accounts is not set")

        for key, value in data.items():
            setattr(oauth_account, key, value)

        if self.auto_commit:
            await self.session.commit()

        return user


class SQLAlchemyRoleRepository(SQLAlchemyAsyncRepository[SQLARoleT], Generic[SQLARoleT, SQLAUserT]):
    """SQLAlchemy implementation of role persistence layer."""

    def __init__(self, session: AsyncSession, model_type: type[SQLARoleT], **kwargs: Any) -> None:
        """Repository for users.

        Args:
            session: Session managing the unit-of-work for the operation.
            model_type: A subclass of `SQLAlchemyRoleModel`.
            kwargs: Additional keyword arguments to pass to superclass.
        """
        self.model_type = model_type
        super().__init__(session=session)

    async def assign_role(self, user: SQLAUserT, role: SQLARoleT) -> SQLAUserT:
        """Add a role to a user.

        Args:
            user: The user to receive the role.
            role: The role to add to the user.
        """
        if not hasattr(user, "roles"):
            raise ImproperlyConfiguredException("User.roles is not set")
        user.roles.append(role)  # pyright: ignore

        if self.auto_commit:
            await self.session.commit()

        return user

    async def revoke_role(self, user: SQLAUserT, role: SQLARoleT) -> SQLAUserT:
        """Revoke a role from a user.

        Args:
            user: The user to revoke the role from.
            role: The role to revoke from the user.
        """
        if not hasattr(user, "roles"):
            raise ImproperlyConfiguredException("User.roles is not set")
        user.roles.remove(role)  # pyright: ignore
        if self.auto_commit:
            await self.session.commit()
        return user
