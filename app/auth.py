"""Local dev OIDC issuer (authorization code + PKCE) and request authentication.

Bearer credentials are either an RS256 access token minted here, or an opaque
org-scoped API token (`acc_...`, stored as a SHA-256 hash).
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from .db import ApiToken, Membership, Org, Session, User

ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:8000/oidc")
AUDIENCE = "access-control-api"
TOKEN_TTL_S = 3600
CLIENTS = {  # client_id -> allowed redirect URIs (exact match)
    "admin-ui": set(
        os.getenv(
            "UI_REDIRECT_URIS",
            "http://localhost:5173/callback,http://localhost:4173/callback,http://localhost:8000/callback",
        ).split(",")
    )
}
ROLE_RANK = {"controller": 0, "viewer": 1, "operator": 2, "admin": 3}

if pem := os.getenv("OIDC_PRIVATE_KEY_PEM"):
    _key = serialization.load_pem_private_key(pem.encode(), password=None)
else:  # ponytail: per-process key, tokens die on restart; set OIDC_PRIVATE_KEY_PEM to persist
    _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public = _key.public_key()
KID = hashlib.sha256(_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]
_codes: dict[str, dict] = {}  # ponytail: in-memory auth codes, single API replica only

router = APIRouter(prefix="/oidc", tags=["oidc"])


@dataclass(frozen=True)
class Principal:
    sub: str
    org_id: int
    role: str
    kind: str  # user | token


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_api_token() -> str:
    return "acc_" + secrets.token_urlsafe(32)


def mint_access_token(sub: str, org_id: int, role: str, email: str = "", ttl: int = TOKEN_TTL_S) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "email": email, "org_id": org_id, "role": role,
              "iat": now, "exp": now + ttl, "scope": "openid profile email"}
    return jwt.encode(claims, _key, algorithm="RS256", headers={"kid": KID})


def principal_from_token(token: str) -> Principal:
    if token.startswith("acc_"):
        with Session() as s:
            t = s.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(token), ApiToken.revoked.is_(False)))
        if t is None:
            raise HTTPException(401, "invalid api token")
        return Principal(f"token:{t.id}:{t.name}", t.org_id, t.role, "token")
    try:
        c = jwt.decode(token, _public, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER)
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid token: {e}") from None
    return Principal(c["sub"], int(c["org_id"]), c["role"], "user")


def require(min_role: str):
    def dep(request: Request) -> Principal:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        p = principal_from_token(token)
        if ROLE_RANK.get(p.role, -1) < ROLE_RANK[min_role]:
            raise HTTPException(403, f"requires role {min_role}")
        return p

    return Depends(dep)


# --- OIDC endpoints -------------------------------------------------------------------------


@router.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@router.get("/jwks")
def jwks():
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_public))
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}


def _check_client(client_id: str, redirect_uri: str) -> None:
    if redirect_uri not in CLIENTS.get(client_id, ()):
        raise HTTPException(400, "unknown client_id or redirect_uri")


@router.get("/authorize", response_class=HTMLResponse)
def authorize_form(client_id: str, redirect_uri: str, code_challenge: str, state: str = "",
                   response_type: str = "code", code_challenge_method: str = "S256", nonce: str = "", scope: str = ""):
    _check_client(client_id, redirect_uri)
    if response_type != "code" or code_challenge_method != "S256":
        raise HTTPException(400, "only response_type=code with PKCE S256 is supported")
    with Session() as s:
        members = s.execute(select(User, Org, Membership.role).join(Membership, Membership.user_id == User.id)
                            .join(Org, Org.id == Membership.org_id).order_by(User.id, Org.id)).all()
    hidden = "".join(f'<input type="hidden" name="{k}" value="{html.escape(v)}">' for k, v in
                     {"client_id": client_id, "redirect_uri": redirect_uri, "code_challenge": code_challenge,
                      "state": state, "nonce": nonce}.items())
    buttons = "".join(
        f'<button name="membership" value="{u.id}:{o.id}">{html.escape(u.name)} &lt;{html.escape(u.email)}&gt; '
        f'&middot; {html.escape(o.name)} &middot; {role}</button><br>' for u, o, role in members)
    return f"""<!doctype html><title>Dev sign-in</title><body style="font-family:system-ui;max-width:40rem;margin:3rem auto">
<h1>Local dev issuer</h1><p>Development only. Pick an identity; no password is checked.</p>
<form method="post">{hidden}{buttons}</form></body>"""


@router.post("/authorize")
def authorize_submit(client_id: str = Form(), redirect_uri: str = Form(), code_challenge: str = Form(),
                     membership: str = Form(), state: str = Form(""), nonce: str = Form("")):
    _check_client(client_id, redirect_uri)
    user_id, org_id = (int(x) for x in membership.split(":"))
    with Session() as s:
        m = s.get(Membership, (user_id, org_id))
        user = s.get(User, user_id)
    if m is None:
        raise HTTPException(400, "no such membership")
    code = secrets.token_urlsafe(24)
    _codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "challenge": code_challenge,
                    "user_id": user.id, "email": user.email, "name": user.name, "org_id": org_id, "role": m.role,
                    "nonce": nonce, "exp": time.time() + 60}
    return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=302)


@router.post("/token")
def token(grant_type: str = Form(), code: str = Form(), redirect_uri: str = Form(), client_id: str = Form(),
          code_verifier: str = Form()):
    if grant_type != "authorization_code":
        raise HTTPException(400, "unsupported_grant_type")
    c = _codes.pop(code, None)  # single use
    if not c or c["exp"] < time.time() or c["client_id"] != client_id or c["redirect_uri"] != redirect_uri:
        raise HTTPException(400, "invalid_grant")
    if not secrets.compare_digest(b64url(hashlib.sha256(code_verifier.encode()).digest()), c["challenge"]):
        raise HTTPException(400, "invalid_grant: PKCE verification failed")
    sub = f"user:{c['user_id']}"
    now = int(time.time())
    id_token = jwt.encode({"iss": ISSUER, "aud": client_id, "sub": sub, "email": c["email"], "name": c["name"],
                           "nonce": c["nonce"], "org_id": c["org_id"], "role": c["role"], "iat": now,
                           "exp": now + TOKEN_TTL_S}, _key, algorithm="RS256", headers={"kid": KID})
    return {"access_token": mint_access_token(sub, c["org_id"], c["role"], c["email"]), "id_token": id_token,
            "token_type": "Bearer", "expires_in": TOKEN_TTL_S}


@router.get("/userinfo")
def userinfo(p: Principal = require("viewer")):
    return {"sub": p.sub, "org_id": p.org_id, "role": p.role}
