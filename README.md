# Orbit Auth JWT

`orbit-auth-jwt` is a separately installable JWT verification adapter for `orbit-auth`. It implements
the capability's provider-neutral `TokenVerifier` contract using PyJWT; neither Core nor
`orbit-auth` depends on PyJWT.

```bash
pip install orbit-core orbit-auth orbit-auth-jwt
```

This base installation supports HMAC algorithms. For RSA, ECDSA, PSS, or EdDSA verification,
install the optional cryptography dependency:

```bash
pip install 'orbit-auth-jwt[asymmetric]'
```

Configuring one of those algorithm families without the extra fails immediately with an
installation hint instead of looking like an invalid end-user token at request time.

Compose it with `orbit-auth`'s bearer authenticator:

```python
from orbit_auth import BearerAuthenticator
from orbit_auth_jwt import PyJWTVerifier

authenticator = BearerAuthenticator(
    PyJWTVerifier(
        key="load-this-from-a-secret-manager",
        algorithms=("HS256",),
        issuer="https://identity.example",
        audience="my-service",
    ),
    provider="jwt",
)
```

The verifier requires an explicit algorithm allowlist, rejects `none`, requires subject, token ID,
issued-at, and expiry claims, bounds input and policy metadata, validates scopes, and returns
`orbit-auth`'s payload-safe `Token` model. One verifier may allow multiple algorithms from the same key
family for controlled key rotation, but it rejects allowlists that mix HMAC (`HS*`) with asymmetric
algorithms to prevent algorithm-confusion configurations. It does not issue tokens, fetch JWKS
keys, manage secrets, or provide key rotation. Prefer asymmetric signing keys for distributed
services and load key material from a secret manager; never commit production signing secrets.
Configure issuer, audience, expiry, and revocation policy for the deployment. Keep asymmetric
verification keys public-only; never pass the signing private key to a verifier.

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy
```

## Status

This package is pre-alpha; its API is not stable and it is not yet a published release. It supports
Python 3.11 through 3.14.

Licensed under Apache-2.0.

