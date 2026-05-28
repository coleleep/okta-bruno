#!/usr/bin/env python3
"""Mint a bearer token for the Okta Management API via private_key_jwt.

The Org Authorization Server (/oauth2/v1/token, no authServerId) requires
client authentication via private_key_jwt — basic auth with a client
secret does NOT work for Okta API access scopes.

Bruno's QuickJS sandbox cannot perform RSA signing in pre-request scripts,
so this helper does it externally. Pipe the output into your clipboard:

    python3 scripts/get_okta_token.py | pbcopy

Then paste into Bruno's `bearerToken` env variable. Token lifetime is
configurable in the auth server policy (default 1 hour).

Configuration: pass --config to point at a JSON file with these fields:

    {
      "orgUrl": "https://your-org.okta.com",
      "clientId": "0oa...",
      "scopes": "okta.users.read okta.groups.read",
      "privateJwk": { ...JWK... }
    }

Or set them in env vars: OKTA_ORG_URL, OKTA_API_CLIENT_ID,
OKTA_API_SCOPES, OKTA_API_PRIVATE_JWK (the JWK as a JSON string).

CLI flags override config file values which override env vars.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import requests

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
except ImportError:
    print(
        "Missing dependency: install with `pip3 install cryptography --break-system-packages`",
        file=sys.stderr,
    )
    sys.exit(2)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_int(s: str) -> int:
    """Decode a base64url-encoded big-endian integer (per RFC 7518)."""
    padding_needed = -len(s) % 4
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * padding_needed), "big")


def jwk_to_rsa_private_key(jwk: dict[str, Any]) -> rsa.RSAPrivateKey:
    """Convert an RSA private JWK to a cryptography RSAPrivateKey."""
    if jwk.get("kty") != "RSA":
        raise ValueError(f"Expected RSA JWK, got kty={jwk.get('kty')}")
    required = ["n", "e", "d", "p", "q", "dp", "dq", "qi"]
    missing = [k for k in required if k not in jwk]
    if missing:
        raise ValueError(f"JWK missing required RSA private fields: {missing}")
    public = RSAPublicNumbers(e=b64url_int(jwk["e"]), n=b64url_int(jwk["n"]))
    private = RSAPrivateNumbers(
        p=b64url_int(jwk["p"]),
        q=b64url_int(jwk["q"]),
        d=b64url_int(jwk["d"]),
        dmp1=b64url_int(jwk["dp"]),
        dmq1=b64url_int(jwk["dq"]),
        iqmp=b64url_int(jwk["qi"]),
        public_numbers=public,
    )
    return private.private_key()


def sign_jwt(jwk: dict[str, Any], claims: dict[str, Any]) -> str:
    alg = jwk.get("alg", "RS256")
    hash_map = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}
    if alg not in hash_map:
        raise ValueError(f"Unsupported alg: {alg} (supports RS256/RS384/RS512)")

    header = {"alg": alg, "typ": "JWT"}
    if "kid" in jwk:
        header["kid"] = jwk["kid"]

    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    private_key = jwk_to_rsa_private_key(jwk)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hash_map[alg])

    return f"{header_b64}.{payload_b64}.{b64url(signature)}"


def load_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg: dict[str, Any] = {}

    if args.config:
        with open(args.config) as f:
            cfg.update(json.load(f))

    env_map = {
        "orgUrl": "OKTA_ORG_URL",
        "clientId": "OKTA_API_CLIENT_ID",
        "scopes": "OKTA_API_SCOPES",
        "privateJwk": "OKTA_API_PRIVATE_JWK",
    }
    for key, env_name in env_map.items():
        if key not in cfg and env_name in os.environ:
            value = os.environ[env_name]
            if key == "privateJwk":
                value = json.loads(value)
            cfg[key] = value

    if args.org_url:
        cfg["orgUrl"] = args.org_url
    if args.client_id:
        cfg["clientId"] = args.client_id
    if args.scopes:
        cfg["scopes"] = args.scopes
    if args.jwk_file:
        cfg["privateJwk"] = json.loads(Path(args.jwk_file).read_text())

    missing = [k for k in ("orgUrl", "clientId", "scopes", "privateJwk") if k not in cfg]
    if missing:
        print(f"Missing config: {missing}", file=sys.stderr)
        print("Set via --config, env vars, or CLI flags. See --help.", file=sys.stderr)
        sys.exit(2)

    cfg["orgUrl"] = cfg["orgUrl"].rstrip("/")
    return cfg


def get_token(cfg: dict[str, Any]) -> dict[str, Any]:
    token_endpoint = f"{cfg['orgUrl']}/oauth2/v1/token"

    now = int(time.time())
    claims = {
        "iss": cfg["clientId"],
        "sub": cfg["clientId"],
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }

    assertion = sign_jwt(cfg["privateJwk"], claims)

    resp = requests.post(
        token_endpoint,
        data={
            "grant_type": "client_credentials",
            "scope": cfg["scopes"],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        },
        headers={"Accept": "application/json"},
        timeout=30,
    )
    if not resp.ok:
        print(f"Token request failed: {resp.status_code}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)

    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--org-url", help="Okta org URL, e.g. https://acme.okta.com")
    parser.add_argument("--client-id", help="API service app client ID")
    parser.add_argument("--scopes", help="Space-separated Okta API scopes")
    parser.add_argument("--jwk-file", help="Path to private JWK JSON file")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Print full JSON response instead of just the access_token",
    )
    parser.add_argument(
        "--jwt-only",
        action="store_true",
        help="Sign and print the client_assertion JWT only — skip the token exchange. "
        "Useful for pasting into Bruno's clientAssertion env var so Flow 09 can run the exchange.",
    )
    args = parser.parse_args()

    cfg = load_config(args)

    if args.jwt_only:
        token_endpoint = f"{cfg['orgUrl']}/oauth2/v1/token"
        now = int(time.time())
        claims = {
            "iss": cfg["clientId"],
            "sub": cfg["clientId"],
            "aud": token_endpoint,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        }
        print(sign_jwt(cfg["privateJwk"], claims))
        return 0

    response = get_token(cfg)

    if args.full:
        print(json.dumps(response, indent=2))
    else:
        print(response["access_token"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
