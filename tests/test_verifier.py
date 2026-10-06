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
"""Policy validation for the separately installed PyJWT adapter."""

import sys
from datetime import UTC, datetime
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from orbit_auth import Token

from orbit_auth_jwt import PyJWTVerifier


def test_verifier_maps_verified_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC).timestamp()
    calls: dict[str, object] = {}

    def decode(credential: str, key: str, **kwargs: object) -> dict[str, object]:
        calls.update(credential=credential, key=key, kwargs=kwargs)
        return {
            "sub": "user-1",
            "jti": "token-1",
            "iat": now,
            "exp": now + 60,
            "scope": "read write",
            "iss": "https://issuer.example",
        }

    monkeypatch.setitem(sys.modules, "jwt", SimpleNamespace(decode=decode))
    token = PyJWTVerifier(
        "secret", issuer="https://issuer.example", audience="api", algorithms=("HS256",)
    ).verify("compact")
    assert isinstance(token, Token)
    assert token.subject == "user-1"
    assert token.scopes == frozenset({"read", "write"})
    kwargs = calls["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["algorithms"] == ["HS256"]
    assert kwargs["options"] == {"require": ["sub", "jti", "iat", "exp"]}


def test_verifier_accepts_a_real_signed_token_and_rejects_tampering() -> None:
    now = int(datetime.now(UTC).timestamp())
    secret = "test-secret-that-is-not-for-production"
    credential = jwt.encode(
        {
            "sub": "signed-user",
            "jti": "signed-token",
            "iat": now,
            "exp": now + 60,
            "iss": "https://issuer.example",
            "aud": "orbit-api",
            "scope": "read write",
        },
        secret,
        algorithm="HS256",
    )
    verifier = PyJWTVerifier(
        secret,
        algorithms=("HS256",),
        issuer="https://issuer.example",
        audience="orbit-api",
    )

    token = verifier.verify(credential)

    assert token.subject == "signed-user"
    assert token.scopes == frozenset({"read", "write"})
    header, payload, signature = credential.split(".")
    changed_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(ValueError, match="invalid"):
        verifier.verify(f"{header}.{payload}.{changed_signature}")


def test_verifier_accepts_a_real_rsa_signed_token() -> None:
    """The documented asymmetric extra supports public-key verification end to end."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(datetime.now(UTC).timestamp())
    credential = jwt.encode(
        {"sub": "rsa-user", "jti": "rsa-token", "iat": now, "exp": now + 60},
        private_key_pem,
        algorithm="RS256",
    )

    token = PyJWTVerifier(public_key_pem, algorithms=("RS256",)).verify(credential)

    assert token.subject == "rsa-user"
    assert token.token_id == "rsa-token"


def test_asymmetric_configuration_explains_missing_optional_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Users get a configuration hint before serving traffic without crypto support."""
    monkeypatch.setattr("orbit_auth_jwt.verifier.find_spec", lambda _name: None)
    with pytest.raises(ImportError, match=r"orbit-auth-jwt\[asymmetric\]"):
        PyJWTVerifier("public-key", algorithms=("RS256",))


def test_verifier_hides_backend_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def decode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("signature details")

    monkeypatch.setitem(sys.modules, "jwt", SimpleNamespace(decode=decode))
    with pytest.raises(ValueError, match="invalid") as error:
        PyJWTVerifier("secret").verify("compact")
    assert "signature details" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": "x" * 256},
        {"issuer": "issuer\n"},
        {"audience": "x" * 256},
        {"audience": ("api", "x" * 256)},
        {"audience": tuple(f"api-{index}" for index in range(1_025))},
        {"algorithms": ("HS256", "none")},
        {"algorithms": ("HS256", "RS256")},
        {"algorithms": ("RS256", "HS256")},
        {"algorithms": ("HS\n256",)},
        {"algorithms": tuple(f"ALG{index}" for index in range(17))},
        {"leeway": float("inf")},
        {"leeway": 86_401},
    ],
)
def test_verifier_rejects_unbounded_or_unsafe_policy(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        PyJWTVerifier("secret", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("credential", ["", 123])
def test_verifier_rejects_empty_or_non_string_credentials(credential: object) -> None:
    with pytest.raises(ValueError, match="invalid"):
        PyJWTVerifier("secret").verify(credential)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": 1, "jti": "id", "iat": 1, "exp": 2},
        {"sub": "u", "jti": "id", "iat": 1, "exp": 2, "scope": [""]},
        {"sub": "u", "jti": "id", "iat": 1, "exp": 2, "typ": 1},
        {"sub": "u", "jti": "id", "iat": True, "exp": 2},
    ],
)
def test_verifier_rejects_malformed_claims(
    monkeypatch: pytest.MonkeyPatch, claims: dict[str, object]
) -> None:
    monkeypatch.setitem(sys.modules, "jwt", SimpleNamespace(decode=lambda *args, **kwargs: claims))
    with pytest.raises(ValueError, match="invalid"):
        PyJWTVerifier("secret").verify("compact")


def test_verifier_bounds_scope_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    claims = {
        "sub": "u",
        "jti": "id",
        "iat": 1,
        "exp": 2,
        "scope": [f"scope-{index}" for index in range(1_025)],
    }
    monkeypatch.setitem(sys.modules, "jwt", SimpleNamespace(decode=lambda *args, **kwargs: claims))
    with pytest.raises(ValueError, match="invalid"):
        PyJWTVerifier("secret").verify("compact")
