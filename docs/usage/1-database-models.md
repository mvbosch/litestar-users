# Database models

## The user model

The [SQLAlchemyUserMixin][litestar_users.adapter.sqlalchemy.mixins.SQLAlchemyUserMixin] provides the following columns:

* `email`: str
* `password_hash`: str
* `is_active`: bool
* `is_verified`: bool

### SQLAlchemy User

!!! important
    Litestar-Users is reliant on the [SQLAlchemyPlugin][advanced_alchemy.extensions.litestar.plugins.SQLAlchemyInitPlugin] for session management and dependency injection, this ensures that no more than one SQLAlchemy session is spun up per request lifecycle.

```python
from advanced_alchemy.base import UUIDBase
from litestar_users.adapter.sqlalchemy.mixins import SQLAlchemyUserMixin


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""
```

The user model can be extended arbitrarily:

```python
from advanced_alchemy.base import UUIDBase
from litestar_users.adapter.sqlalchemy.mixins import SQLAlchemyUserMixin
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
    You must set your own `User.roles` relationship and association table, since this is dependent on your own `__tablename__` definitions.

### SQLAlchemy Role

```python
from uuid import UUID
from advanced_alchemy.base import UUIDBase
from litestar_users.adapter.sqlalchemy.mixins import (
    SQLAlchemyUserMixin,
    SQLAlchemyRoleMixin,
)
from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship


class Role(UUIDBase, SQLAlchemyRoleMixin):
    """Role model."""


class User(UUIDBase, SQLAlchemyUserMixin):
    """User model."""

    roles: Mapped[list[Role]] = relationship(
        "Role", secondary="user_role", lazy="selectin"
    )


class UserRole(UUIDBase):
    """User role association model."""

    user_id: Mapped[UUID] = mapped_column(Uuid(), ForeignKey("user.id"))
    role_id: Mapped[UUID] = mapped_column(Uuid(), ForeignKey("role.id"))
```

Just as with the user model, you can define arbitrary custom columns:

```python
from datetime import datetime

from advanced_alchemy.base import UUIDBase
from litestar_users.adapter.sqlalchemy.mixins import SQLAlchemyRoleMixin
from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


class Role(UUIDBase, SQLAlchemyRoleMixin):
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=datetime.now)
```
