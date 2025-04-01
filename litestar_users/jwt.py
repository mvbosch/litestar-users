from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union, cast

import jwt

JWT_ALGORITHM = "HS256"


def generate_jwt(
    data: dict,
    secret: str,
    lifetime_seconds: Optional[int] = None,
    algorithm: str = JWT_ALGORITHM,
) -> str:
    payload = data.copy()
    if lifetime_seconds:
        expire = datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds)
        payload["exp"] = expire
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_jwt(
    encoded_jwt: str,
    secret: str,
    audience: list[str],
    algorithms: Union[list[str], None] = None,
) -> dict[str, Any]:
    _algorithms = algorithms or [JWT_ALGORITHM]
    return cast(
        dict[str, Any],
        jwt.decode(
            encoded_jwt,
            secret,
            audience=audience,
            algorithms=_algorithms,
        ),
    )
