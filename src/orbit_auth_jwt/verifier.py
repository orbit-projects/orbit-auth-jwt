# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Verify JWT signatures and adapt verified claims to orbit-auth's token model."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from importlib.util import find_spec
from typing import Any

from orbit_auth import Token

_MAX_ALGORITHMS = 16
_MAX_AUDIENCES = 1_024
_MAX_SCOPES = 1_024
_MAX_TEXT = 255
_MAX_TOKEN_LENGTH = 16_384
_MAX_LEEWAY_SECONDS = 86_400
_HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_CRYPTO_ALGORITHM_PREFIXES = ("RS", "ES", "PS")
_CRYPTO_ALGORITHMS = frozenset({"EdDSA"})


class PyJWTVerifier:
    """Verify JWT credentials through PyJWT and return Orbit Auth's provider-neutral token.

    An explicit algorithm allowlist and required claims prevent accepting unsigned or incomplete
    tokens. Token issuance, JWKS discovery, key rotation, and credential storage are intentionally
    outside this verifier.
    """

    def __init__(
        self,
        key: Any,
        *,
        algorithms: tuple[str, ...] = ("HS256",),
        issuer: str | None = None,
        audience: str | tuple[str, ...] | None = None,
        leeway: float = 0,
    ) -> None:
        """Freeze a bounded verifier policy for one key and explicit algorithm allowlist."""
        if (
            not isinstance(algorithms, tuple)
            or not algorithms
            or len(algorithms) > _MAX_ALGORITHMS
            or any(
                not isinstance(algorithm, str)
                or not 1 <= len(algorithm) <= 32
                or algorithm.lower() == "none"
                or any(ord(character) < 33 or ord(character) == 127 for character in algorithm)
                for algorithm in algorithms
            )
        ):
            raise ValueError("JWT algorithms must explicitly exclude 'none'.")
        if any(algorithm in _HMAC_ALGORITHMS for algorithm in algorithms) and any(
            algorithm not in _HMAC_ALGORITHMS for algorithm in algorithms
        ):
            raise ValueError("JWT algorithm allowlists cannot mix HMAC and asymmetric families.")
        if (
            any(_requires_cryptography(algorithm) for algorithm in algorithms)
            and find_spec("cryptography") is None
        ):
            raise ImportError(
                "Asymmetric JWT algorithms require cryptography; install "
                "orbit-auth-jwt[asymmetric]."
            )
        if (
            isinstance(leeway, bool)
            or not isinstance(leeway, (int, float))
            or not math.isfinite(leeway)
            or not 0 <= leeway <= _MAX_LEEWAY_SECONDS
        ):
            raise ValueError("JWT leeway must be finite and between zero and one day.")
        if issuer is not None and not _valid_text(issuer):
            raise ValueError("JWT issuer must be bounded, nonempty printable text.")
        if audience is not None:
            audiences: tuple[str, ...]
            if isinstance(audience, str):
                audiences = (audience,)
            elif isinstance(audience, tuple):
                audiences = audience
            else:
                raise ValueError("JWT audience must be a nonempty string or tuple of strings.")
            if (
                not audiences
                or len(audiences) > _MAX_AUDIENCES
                or any(not _valid_text(item) for item in audiences)
            ):
                raise ValueError("JWT audience values must be bounded printable strings.")
        self._key = key
        self._algorithms = algorithms
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway

    def verify(self, credential: str) -> Token:
        """Validate a compact JWT and return detached, validated token metadata."""
        if not isinstance(credential, str) or not credential or len(credential) > _MAX_TOKEN_LENGTH:
            raise ValueError("JWT credential is invalid.")
        try:
            import jwt

            claims = jwt.decode(
                credential,
                self._key,
                algorithms=list(self._algorithms),
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={"require": ["sub", "jti", "iat", "exp"]},
            )
            issued_at = datetime.fromtimestamp(_numeric_date(claims["iat"]), UTC)
            expires_at = datetime.fromtimestamp(_numeric_date(claims["exp"]), UTC)
            subject = claims["sub"]
            token_id = claims["jti"]
            if not isinstance(subject, str) or not isinstance(token_id, str):
                raise ValueError("JWT subject and ID must be strings.")
            scopes = _scopes(claims.get("scope", claims.get("scp", ())))
            token_type = claims.get("typ", "access")
            if not isinstance(token_type, str):
                raise ValueError("JWT type must be a string.")
            return Token(
                token_id=token_id,
                subject=subject,
                token_type=token_type.lower(),
                issued_at=issued_at,
                expires_at=expires_at,
                scopes=scopes,
                claims=dict(claims),
            )
        except Exception:
            # Do not leak backend messages or retain them in traceback cause chains.
            raise ValueError("JWT credential is invalid.") from None


def _valid_text(value: object) -> bool:
    """Return whether a policy string is bounded and contains no controls."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= _MAX_TEXT
        and all(character.isprintable() for character in value)
    )


def _requires_cryptography(algorithm: str) -> bool:
    """Return whether PyJWT needs its optional cryptography extra for this algorithm family."""
    return algorithm in _CRYPTO_ALGORITHMS or algorithm.startswith(_CRYPTO_ALGORITHM_PREFIXES)


def _numeric_date(value: object) -> float:
    """Require finite numeric date claims without accepting booleans or text coercion."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("JWT date claim must be a finite number.")
    return float(value)


def _scopes(value: object) -> frozenset[str]:
    """Normalize and bound scope claims before they become Core authorization metadata."""
    if isinstance(value, str):
        values = value.split()
    elif isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
    else:
        raise ValueError("JWT scopes must be a string or collection of strings.")
    if len(values) > _MAX_SCOPES:
        raise ValueError("JWT scopes exceed the configured cardinality limit.")
    if any(
        not isinstance(item, str)
        or not 1 <= len(item) <= _MAX_TEXT
        or any(not character.isprintable() or character.isspace() for character in item)
        for item in values
    ):
        raise ValueError("JWT scopes contain invalid identifiers.")
    return frozenset(values)


__all__ = ["PyJWTVerifier"]
