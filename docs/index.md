# Litestar-Users documentation

Litestar-Users is an authentication, authorization and user management package for [Litestar](https://github.com/litestar-api/litestar) v2.1.1 and above.

## Features

- Session, JWT and JWTCookie authentication backends
- Customizable pre- and post-operation hooks
- Optional RBAC (Role based access control)
- Pre-configured route handlers for:
  - Authentication
  - Registration and verification
  - Password recovery
  - Administrative user and role management

## Installation

`pip install litestar-users`

  or with OAuth2 support:

`pip install litestar-users[oauth2]`

## Full example

Example application code can be viewed [here](https://github.com/LonelyVikingMichael/litestar-users/blob/main/examples/basic.py).
