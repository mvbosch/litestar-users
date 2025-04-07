from dataclasses import dataclass
from uuid import UUID

__all__ = [
    "AuthenticationSchema",
    "ForgotPasswordSchema",
    "ResetPasswordSchema",
    "UserRoleSchema",
]


@dataclass
class AuthenticationSchema:
    """User authentication schema."""

    email: str
    password: str


@dataclass
class ForgotPasswordSchema:
    """Forgot password schema."""

    email: str


@dataclass
class ResetPasswordSchema:
    """Reset password schema."""

    token: str
    password: str


@dataclass
class UserRoleSchema:
    """User role association schema."""

    user_id: UUID
    role_id: UUID


@dataclass
class OAuth2AuthorizeSchema:
    """OAuth2 authorize schema."""

    authorization_url: str
