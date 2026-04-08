# Database models

## The user model

The [SQLAlchemyUserMixin][litestar_users.mixins.SQLAlchemyUserMixin] provides the following columns:

* `email`: str
* `password_hash`: str
* `is_active`: bool
* `is_verified`: bool

### SQLAlchemy User

!!! important
    Litestar-Users is reliant on the [SQLAlchemyInitPlugin][advanced_alchemy.extensions.litestar.SQLAlchemyInitPlugin] for session management and dependency injection, this ensures that no more than one SQLAlchemy session is spun up per request lifecycle.

```python
from advanced_alchemy.base import UUIDBase
from litestar_users.mixins import SQLAlchemyUserMixin


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""
```

The user model can be extended arbitrarily:

```python
from advanced_alchemy.base import UUIDBase
from litestar_users.mixins import SQLAlchemyUserMixin
from sqlalchemy import Integer
from sqlalchemy.orm import Mapped, mapped_column


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""

    token_count: Mapped[int] = mapped_column(Integer())
```

!!! note
    You can skip the next section if you're not making use of Litestar User's built in RBAC.

## The role model

For RBAC (role based access control), additionally set up a `Role` model along with a user-role association table.

!!! note
    You must define your own `User.roles` relationship and association table, as these depend on your own `__tablename__` definitions.

### SQLAlchemy Role

Use a Core `Table` for the association so that no extra ORM entity is introduced:

```python
from advanced_alchemy.base import UUIDBase, orm_registry
from litestar_users.mixins import SQLAlchemyUserMixin, SQLAlchemyRoleMixin
from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.orm import Mapped, relationship

user_role = Table(
    "user_role",
    orm_registry.metadata,
    Column("user_id", ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("role.id", ondelete="CASCADE"), primary_key=True),
)


class Role(UUIDBase, SQLAlchemyRoleMixin):
    """Role model."""


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""

    roles: Mapped[list[Role]] = relationship(secondary="user_role", lazy="selectin")
```

Just as with the user model, you can define arbitrary custom columns on `Role`:

```python
from datetime import datetime

from advanced_alchemy.base import UUIDBase
from litestar_users.mixins import SQLAlchemyRoleMixin
from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


class Role(UUIDBase, SQLAlchemyRoleMixin):
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=datetime.now)
```

!!! note
    You can skip the next section if you're not making use of Litestar Users with OAuth2.

## The OAuth account model

For OAuth2, set up an `OAuthAccount` model with a foreign key back to the user.

### SQLAlchemy OAuth Account

```python
from uuid import UUID
from advanced_alchemy.base import UUIDBase
from litestar_users.mixins import (
    SQLAlchemyOAuthAccountMixin,
    SQLAlchemyUserMixin,
)
from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship


class OAuthAccount(UUIDBase, SQLAlchemyOAuthAccountMixin):
    """OAuth account model."""

    user_id: Mapped[UUID] = mapped_column(Uuid(), ForeignKey("user.id"))


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""

    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(
        OAuthAccount, lazy="selectin"
    )
```

## Repositories

Litestar-Users no longer ships its own repository classes. Instead, you subclass `SQLAlchemyAsyncRepository` from [advanced-alchemy](https://github.com/litestar-org/advanced-alchemy) and set `model_type` as a class variable. The plugin will instantiate the repository on every request.

```python
from advanced_alchemy.repository import SQLAlchemyAsyncRepository

from .models import OAuthAccount, Role, User


class UserRepository(SQLAlchemyAsyncRepository[User]):
    model_type = User


class RoleRepository(SQLAlchemyAsyncRepository[Role]):
    model_type = Role


class OAuthAccountRepository(SQLAlchemyAsyncRepository[OAuthAccount]):
    model_type = OAuthAccount
```

Pass these classes to `LitestarUsersConfig`:

* `user_repository_class` - required for all setups.
* `oauth_account_repository_class` - required when using OAuth2.
* `role_repository_class` - passed inside `RoleManagementHandlerConfig` when using RBAC.
